/*
 * setup.c — セットアップウィザード
 *
 * あそビューのAPIキーを入力することで即座に本番環境に移行できる初期設定画面。
 * ADMIN_KEY が未設定（デフォルト値）のときのみ /api/v1/setup への書き込みを許可。
 */

#include "setup.h"
#include "mongoose.h"
#include "db_driver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_ADMIN_KEY "asoview-admin-dev"

/* ─── URL デコード（form-urlencoded 用） ──────────────────────────────────── */
static void url_decode(const char *src, size_t src_len, char *dst, size_t dst_size) {
    size_t oi = 0;
    for (size_t i = 0; i < src_len && oi + 1 < dst_size; i++) {
        if (src[i] == '%' && i + 2 < src_len) {
            char hex[3] = { src[i+1], src[i+2], '\0' };
            dst[oi++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else if (src[i] == '+') {
            dst[oi++] = ' ';
        } else {
            dst[oi++] = src[i];
        }
    }
    dst[oi] = '\0';
}

/* ─── form フィールド取得 ─────────────────────────────────────────────────── */
static void get_form_field(const char *body, size_t body_len,
                           const char *key, char *out, size_t out_size) {
    out[0] = '\0';
    size_t klen = strlen(key);
    for (size_t i = 0; i + klen + 1 <= body_len; i++) {
        if (memcmp(body + i, key, klen) == 0 && body[i + klen] == '=') {
            size_t vstart = i + klen + 1;
            size_t vend   = vstart;
            while (vend < body_len && body[vend] != '&') vend++;
            url_decode(body + vstart, vend - vstart, out, out_size);
            return;
        }
    }
}

/* ─── .env ファイルの値を上書き or 追記 ───────────────────────────────────── */
static void write_env_key(FILE *fp, const char *key, const char *val) {
    if (val && *val) fprintf(fp, "%s=%s\n", key, val);
}

int setup_is_unconfigured(void) {
    const char *admin_key = getenv("ADMIN_KEY");
    /* 未設定 or デフォルト値のとき true */
    if (!admin_key || !*admin_key) return 1;
    if (strcmp(admin_key, DEFAULT_ADMIN_KEY) == 0) return 1;
    return 0;
}

/* ─── セットアップページ HTML ────────────────────────────────────────────── */
void handle_setup_page(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    (void)hm; (void)db;

    /* 現在の環境変数を読み込んで各フィールドのプレースホルダーに使う */
    const char *cur_jwt      = getenv("JWT_SECRET");
    const char *cur_admin    = getenv("ADMIN_KEY");
    const char *cur_cors     = getenv("CORS_ORIGIN");
    const char *cur_stripe   = getenv("STRIPE_SECRET_KEY");
    const char *cur_stripe_w = getenv("STRIPE_WEBHOOK_SECRET");
    const char *cur_resend   = getenv("RESEND_API_KEY");
    const char *cur_resend_f = getenv("RESEND_FROM");
    const char *cur_frontend = getenv("FRONTEND_URL");
    const char *cur_db_url   = getenv("DATABASE_URL");

    /* 設定済みならマスク表示 */
#define MASKED(v) ((v) && *(v) ? "（設定済み）" : "")
#define PLACEHOLDER(v, dflt) ((v) && *(v) ? "••••••••••••" : (dflt))

    int locked = !setup_is_unconfigured();

    mg_http_reply(c, 200,
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Cache-Control: no-cache\r\n",
        "<!DOCTYPE html><html lang='ja'><head>"
        "<meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Asoview セットアップ</title>"
        "<style>"
        "*{box-sizing:border-box;margin:0;padding:0}"
        "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
        "background:linear-gradient(135deg,#1a1a2e 0%%,#0f0f23 100%%);"
        "min-height:100vh;padding:24px 16px}"
        ".wrap{max-width:720px;margin:0 auto}"
        ".logo{display:flex;align-items:center;gap:10px;margin-bottom:32px}"
        ".logo-icon{width:36px;height:36px}"
        ".logo h1{color:#fff;font-size:22px;font-weight:700}"
        ".logo .ver{color:#e94560;font-size:13px;margin-left:8px;"
        "background:rgba(233,69,96,.15);padding:2px 8px;border-radius:12px}"
        ".card{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);"
        "border-radius:16px;padding:28px;margin-bottom:20px;backdrop-filter:blur(12px)}"
        ".card-title{color:#e94560;font-size:12px;font-weight:700;letter-spacing:.8px;"
        "text-transform:uppercase;margin-bottom:18px;display:flex;align-items:center;gap:6px}"
        ".field{margin-bottom:16px}"
        "label{display:block;color:#ccd;font-size:13px;font-weight:500;margin-bottom:5px}"
        ".req{color:#e94560;margin-left:3px}"
        ".badge-set{color:#22c55e;font-size:11px;margin-left:6px;font-weight:normal}"
        "input[type=text],input[type=password],input[type=email],input[type=url]{"
        "width:100%%;padding:10px 14px;background:rgba(255,255,255,.08);"
        "border:1px solid rgba(255,255,255,.15);border-radius:8px;"
        "color:#fff;font-size:14px;outline:none;transition:border .2s}"
        "input:focus{border-color:#e94560;background:rgba(255,255,255,.1)}"
        "input::placeholder{color:rgba(255,255,255,.35)}"
        ".hint{color:#778;font-size:11px;margin-top:5px;line-height:1.5}"
        ".hint a{color:#60a5fa;text-decoration:none}"
        ".hint a:hover{text-decoration:underline}"
        ".gen-wrap{display:flex;gap:8px}"
        ".gen-wrap input{flex:1}"
        ".btn-gen{padding:10px 14px;background:rgba(233,69,96,.2);color:#e94560;"
        "border:1px solid rgba(233,69,96,.4);border-radius:8px;cursor:pointer;"
        "font-size:12px;font-weight:600;white-space:nowrap;transition:all .2s}"
        ".btn-gen:hover{background:rgba(233,69,96,.35)}"
        ".btn-submit{width:100%%;padding:16px;background:#e94560;color:#fff;border:none;"
        "border-radius:10px;font-size:16px;font-weight:700;cursor:pointer;"
        "margin-top:8px;transition:background .2s}"
        ".btn-submit:hover{background:#c73552}"
        ".btn-submit:disabled{background:#555;cursor:not-allowed}"
        ".locked-banner{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);"
        "border-radius:10px;padding:16px;margin-bottom:20px;color:#86efac;font-size:14px}"
        ".locked-banner strong{color:#22c55e}"
        ".warn-banner{background:rgba(233,69,96,.1);border:1px solid rgba(233,69,96,.3);"
        "border-radius:10px;padding:16px;margin-bottom:20px;color:#fca5a5;font-size:14px}"
        ".status{display:inline-block;width:8px;height:8px;border-radius:50%%;margin-right:6px}"
        ".status.ok{background:#22c55e}.status.ng{background:#e94560}"
        ".section-divider{border:none;border-top:1px solid rgba(255,255,255,.08);margin:8px 0 20px}"
        ".footer{text-align:center;color:#556;font-size:12px;margin-top:24px}"
        ".footer a{color:#60a5fa;text-decoration:none}"
        "</style>"
        "</head><body>"
        "<div class='wrap'>"
        "<div class='logo'>"
        "<svg class='logo-icon' viewBox='0 0 32 32'>"
        "<rect width='32' height='32' rx='7' fill='#e94560'/>"
        "<polygon points='16,5 29,27 3,27' fill='white'/>"
        "<polygon points='16,5 21,15 11,15' fill='#1a1a2e'/>"
        "</svg>"
        "<h1>Asoview <span class='ver'>セットアップ</span></h1>"
        "</div>"
        "%s"  /* locked or warn banner */
        "<form method='POST' action='/api/v1/setup' id='setup-form'>"
        /* ── 認証 ── */
        "<div class='card'>"
        "<div class='card-title'>&#128274; 認証 &amp; セキュリティ</div>"
        "<div class='field'>"
        "<label>JWT_SECRET <span class='req'>*</span>%s</label>"
        "<div class='gen-wrap'>"
        "<input type='password' name='JWT_SECRET' id='jwt_secret' placeholder='%s' %s>"
        "<button type='button' class='btn-gen' onclick='genSecret(\"jwt_secret\")'>生成</button>"
        "</div>"
        "<p class='hint'>JWTトークン署名用シークレット（32文字以上を推奨）</p>"
        "</div>"
        "<div class='field'>"
        "<label>ADMIN_KEY <span class='req'>*</span>%s</label>"
        "<div class='gen-wrap'>"
        "<input type='password' name='ADMIN_KEY' id='admin_key' placeholder='%s' %s>"
        "<button type='button' class='btn-gen' onclick='genSecret(\"admin_key\")'>生成</button>"
        "</div>"
        "<p class='hint'>管理者APIアクセスキー（X-Admin-Key ヘッダーに使用）</p>"
        "</div>"
        "<div class='field'>"
        "<label>CORS_ORIGIN</label>"
        "<input type='url' name='CORS_ORIGIN' placeholder='%s'>"
        "<p class='hint'>フロントエンドのオリジン（例: https://example.com）。未設定で * (全許可)</p>"
        "</div>"
        "</div>"
        /* ── Stripe ── */
        "<div class='card'>"
        "<div class='card-title'>&#128179; Stripe 決済</div>"
        "<div class='field'>"
        "<label>STRIPE_SECRET_KEY%s</label>"
        "<input type='password' name='STRIPE_SECRET_KEY' placeholder='%s'>"
        "<p class='hint'><a href='https://dashboard.stripe.com/apikeys' target='_blank'>"
        "Stripe Dashboard</a> → APIキー → シークレットキー (sk_live_... または sk_test_...)</p>"
        "</div>"
        "<div class='field'>"
        "<label>STRIPE_WEBHOOK_SECRET%s</label>"
        "<input type='password' name='STRIPE_WEBHOOK_SECRET' placeholder='%s'>"
        "<p class='hint'><a href='https://dashboard.stripe.com/webhooks' target='_blank'>"
        "Stripe Webhooks</a> → エンドポイント署名シークレット (whsec_...)</p>"
        "</div>"
        "</div>"
        /* ── メール ── */
        "<div class='card'>"
        "<div class='card-title'>&#9993; メール送信 (Resend)</div>"
        "<div class='field'>"
        "<label>RESEND_API_KEY%s</label>"
        "<input type='password' name='RESEND_API_KEY' placeholder='%s'>"
        "<p class='hint'><a href='https://resend.com/api-keys' target='_blank'>"
        "Resend</a> → APIキー (re_...)</p>"
        "</div>"
        "<div class='field'>"
        "<label>RESEND_FROM</label>"
        "<input type='email' name='RESEND_FROM' placeholder='%s'>"
        "<p class='hint'>送信元メールアドレス（Resendで認証済みドメイン）</p>"
        "</div>"
        "<div class='field'>"
        "<label>FRONTEND_URL</label>"
        "<input type='url' name='FRONTEND_URL' placeholder='%s'>"
        "<p class='hint'>パスワードリセットメール等のリンクに使用するフロントエンドURL</p>"
        "</div>"
        "</div>"
        /* ── データベース ── */
        "<div class='card'>"
        "<div class='card-title'>&#128190; データベース</div>"
        "<div class='field'>"
        "<label>DATABASE_URL%s</label>"
        "<input type='text' name='DATABASE_URL' placeholder='%s'>"
        "<p class='hint'>未設定時は <code style='color:#aaa'>asoview.db</code> (SQLite)。"
        "PostgreSQL例: <code style='color:#aaa'>postgres://user:pass@host:5432/asoview</code>"
        "</p>"
        "</div>"
        "</div>"
        "<button type='submit' class='btn-submit' %s>&#9889; 設定を保存して再起動する</button>"
        "</form>"
        "<p class='footer'>設定は <code style='color:#aaa'>.env</code> ファイルに書き込まれます。"
        "反映には手動またはDockerコンテナの再起動が必要です。"
        " &nbsp;|&nbsp; <a href='/admin'>管理ダッシュボードへ</a></p>"
        "</div>"
        "<script>"
        "function genSecret(id){"
        "  var a=new Uint8Array(32);crypto.getRandomValues(a);"
        "  document.getElementById(id).value=btoa(String.fromCharCode(...a))"
        "    .replace(/[+\\/=]/g,'').substring(0,44);"
        "}"
        /* toggle password visibility */
        "document.querySelectorAll('input[type=password]').forEach(function(el){"
        "  var btn=document.createElement('button');btn.type='button';"
        "  btn.textContent='\\uD83D\\uDC41';btn.title='表示/非表示';"
        "  btn.style='position:absolute;right:10px;top:50%%;transform:translateY(-50%%)';"
        "  btn.style+=';background:none;border:none;cursor:pointer;color:#aaa;font-size:16px';"
        "  btn.onclick=function(){el.type=el.type==='password'?'text':'password'};"
        "  var w=el.parentNode;if(w.classList.contains('gen-wrap')){w.insertBefore(btn,el.nextSibling);}"
        "  else{w.style.position='relative';w.appendChild(btn);}"
        "});"
        "</script>"
        "</body></html>",
        /* banner */
        locked
            ? "<div class='locked-banner'><strong>&#10004; 設定済み</strong>"
              " — ADMIN_KEY が本番値に設定されています。セキュリティのため設定変更は環境変数または"
              " .env ファイルを直接編集してください。</div>"
            : "<div class='warn-banner'>&#9888; <strong>デフォルトキーで動作中</strong>"
              " — 本番公開前にすべてのキーを設定してください。</div>",
        /* JWT_SECRET */
        MASKED(cur_jwt),
        PLACEHOLDER(cur_jwt, "ランダムな32文字以上の文字列"),
        locked ? "disabled" : "",
        /* ADMIN_KEY */
        MASKED(cur_admin),
        PLACEHOLDER(cur_admin, "強力なランダムキー"),
        locked ? "disabled" : "",
        /* CORS_ORIGIN */
        (cur_cors && *cur_cors) ? cur_cors : "https://your-frontend.example.com",
        /* STRIPE_SECRET_KEY */
        MASKED(cur_stripe),
        PLACEHOLDER(cur_stripe, "sk_live_... または sk_test_..."),
        /* STRIPE_WEBHOOK_SECRET */
        MASKED(cur_stripe_w),
        PLACEHOLDER(cur_stripe_w, "whsec_..."),
        /* RESEND_API_KEY */
        MASKED(cur_resend),
        PLACEHOLDER(cur_resend, "re_..."),
        /* RESEND_FROM */
        (cur_resend_f && *cur_resend_f) ? cur_resend_f : "noreply@yourdomain.com",
        /* FRONTEND_URL */
        (cur_frontend && *cur_frontend) ? cur_frontend : "https://your-frontend.example.com",
        /* DATABASE_URL */
        MASKED(cur_db_url),
        PLACEHOLDER(cur_db_url, "asoview.db（SQLite デフォルト）"),
        /* submit button disabled state */
        locked ? "disabled" : ""
    );
#undef MASKED
#undef PLACEHOLDER
}

/* ─── セットアップ保存（POST /api/v1/setup） ──────────────────────────────── */
void handle_setup_save(struct mg_connection *c, struct mg_http_message *hm, DbConn *db) {
    (void)db;

    /* ADMIN_KEY がデフォルト値のときのみ許可 */
    if (!setup_is_unconfigured()) {
        mg_http_reply(c, 403, "Content-Type: application/json\r\n",
                      "{\"error\":\"設定済みの環境では /setup は無効です。"
                      ".env ファイルを直接編集してください\"}");
        return;
    }

    const char *body = hm->body.buf;
    size_t body_len  = hm->body.len;

#define FIELD(name, buf, sz) get_form_field(body, body_len, (name), (buf), (sz))

    char jwt_secret[256]         = {0};
    char admin_key[256]          = {0};
    char cors_origin[512]        = {0};
    char stripe_sk[256]          = {0};
    char stripe_whsec[256]       = {0};
    char resend_api_key[256]     = {0};
    char resend_from[256]        = {0};
    char frontend_url[512]       = {0};
    char database_url[512]       = {0};

    FIELD("JWT_SECRET",            jwt_secret,      sizeof(jwt_secret));
    FIELD("ADMIN_KEY",             admin_key,       sizeof(admin_key));
    FIELD("CORS_ORIGIN",           cors_origin,     sizeof(cors_origin));
    FIELD("STRIPE_SECRET_KEY",     stripe_sk,       sizeof(stripe_sk));
    FIELD("STRIPE_WEBHOOK_SECRET", stripe_whsec,    sizeof(stripe_whsec));
    FIELD("RESEND_API_KEY",        resend_api_key,  sizeof(resend_api_key));
    FIELD("RESEND_FROM",           resend_from,     sizeof(resend_from));
    FIELD("FRONTEND_URL",          frontend_url,    sizeof(frontend_url));
    FIELD("DATABASE_URL",          database_url,    sizeof(database_url));
#undef FIELD

    /* JWT_SECRET と ADMIN_KEY は必須 */
    if (!jwt_secret[0] || !admin_key[0]) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                      "{\"error\":\"JWT_SECRET と ADMIN_KEY は必須です\"}");
        return;
    }

    /* .env ファイルを読み込んで既存値とマージ */
    /* 既存の .env を読み込み（存在する場合） */
    char existing[16384] = {0};
    FILE *fin = fopen(".env", "r");
    if (fin) {
        fread(existing, 1, sizeof(existing) - 1, fin);
        fclose(fin);
    }

    /* .env.new に書き込み後、アトミックにリネーム */
    FILE *fp = fopen(".env.new", "w");
    if (!fp) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                      "{\"error\":\".env ファイルを書き込めませんでした\"}");
        return;
    }

    fprintf(fp, "# Asoview 設定ファイル（セットアップウィザードで生成）\n");
    fprintf(fp, "# 変更後はサーバーを再起動してください\n\n");

    /* 認証 */
    fprintf(fp, "# ── 認証 ──────────────────────────────\n");
    write_env_key(fp, "JWT_SECRET",  jwt_secret);
    write_env_key(fp, "ADMIN_KEY",   admin_key);
    write_env_key(fp, "CORS_ORIGIN", cors_origin);

    /* Stripe */
    fprintf(fp, "\n# ── Stripe 決済 ────────────────────────\n");
    write_env_key(fp, "STRIPE_SECRET_KEY",      stripe_sk);
    write_env_key(fp, "STRIPE_WEBHOOK_SECRET",  stripe_whsec);

    /* メール */
    fprintf(fp, "\n# ── メール (Resend) ─────────────────────\n");
    write_env_key(fp, "RESEND_API_KEY", resend_api_key);
    write_env_key(fp, "RESEND_FROM",    resend_from);
    write_env_key(fp, "FRONTEND_URL",   frontend_url);

    /* DB */
    fprintf(fp, "\n# ── データベース ────────────────────────\n");
    write_env_key(fp, "DATABASE_URL", database_url);

    /* 元の .env にあったが上記で書かれなかったキーを引き継ぐ */
    const char *preserve_keys[] = {
        "PORT", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "AWS_REGION", "AWS_S3_BUCKET",
        "MYSQL_HOST", "MYSQL_USER", "MYSQL_PASSWORD", "MYSQL_DATABASE", "MYSQL_PORT",
        NULL
    };
    for (int ki = 0; preserve_keys[ki]; ki++) {
        const char *k = preserve_keys[ki];
        size_t klen = strlen(k);
        /* existing から該当行を探す */
        const char *p = existing;
        while (*p) {
            if (strncmp(p, k, klen) == 0 && p[klen] == '=') {
                const char *end = strchr(p, '\n');
                size_t line_len = end ? (size_t)(end - p) : strlen(p);
                fprintf(fp, "%.*s\n", (int)line_len, p);
                break;
            }
            const char *nl = strchr(p, '\n');
            if (!nl) break;
            p = nl + 1;
        }
    }

    fclose(fp);

    /* アトミックリネーム */
    if (rename(".env.new", ".env") != 0) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                      "{\"error\":\".env の保存に失敗しました\"}");
        return;
    }

    /* 成功レスポンス（HTMLリダイレクト） */
    mg_http_reply(c, 200,
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Cache-Control: no-cache\r\n",
        "<!DOCTYPE html><html lang='ja'><head>"
        "<meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>設定完了 — Asoview</title>"
        "<style>"
        "*{box-sizing:border-box;margin:0;padding:0}"
        "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
        "background:linear-gradient(135deg,#1a1a2e 0%%,#0f0f23 100%%);"
        "min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}"
        ".card{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);"
        "border-radius:20px;padding:48px 40px;max-width:520px;width:100%%;text-align:center;"
        "backdrop-filter:blur(12px)}"
        ".icon{font-size:56px;margin-bottom:20px}"
        "h1{color:#22c55e;font-size:28px;margin-bottom:12px}"
        "p{color:#aab;font-size:15px;line-height:1.7;margin-bottom:8px}"
        "code{background:rgba(255,255,255,.08);color:#e2e8f0;padding:2px 8px;"
        "border-radius:5px;font-size:13px}"
        ".steps{background:rgba(0,0,0,.25);border-radius:12px;padding:20px 24px;"
        "margin:24px 0;text-align:left}"
        ".steps p{color:#cbd;font-size:14px;margin-bottom:10px}"
        ".steps p:last-child{margin-bottom:0}"
        ".btn{display:inline-block;margin-top:24px;padding:14px 32px;"
        "background:#e94560;color:#fff;border-radius:10px;text-decoration:none;"
        "font-weight:700;font-size:15px;transition:background .2s}"
        ".btn:hover{background:#c73552}"
        "</style></head><body>"
        "<div class='card'>"
        "<div class='icon'>&#9989;</div>"
        "<h1>設定を保存しました</h1>"
        "<p><code>.env</code> ファイルに書き込まれました。</p>"
        "<div class='steps'>"
        "<p>&#9654; 変更を反映するにはサーバーを再起動してください:</p>"
        "<p><code>./asoview-c</code> を <kbd>Ctrl+C</kbd> で停止後、再度起動</p>"
        "<p>Docker の場合: <code>docker restart asoview</code></p>"
        "<p>systemd の場合: <code>systemctl restart asoview</code></p>"
        "</div>"
        "<p style='color:#778;font-size:13px'>再起動後、このセットアップ画面は無効になります。</p>"
        "<a class='btn' href='/admin'>管理ダッシュボードへ</a>"
        "</div>"
        "</body></html>%s", "");
}
