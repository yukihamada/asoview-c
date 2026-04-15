# asoview-c

**Node.js/Python サーバーを捨てて、285KB のシングルバイナリに移行する話。**

[![Tests](https://img.shields.io/badge/tests-90%2F90%20pass-brightgreen)](tests/test_api.c)
[![CI](https://github.com/yukihamada/asoview-c/actions/workflows/ci.yml/badge.svg)](../../actions)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.1.0-blue)](openapi.yaml)

---

## まず動かしてみてほしい

```bash
git clone https://github.com/yukihamada/asoview-c
cd asoview-c
make          # 初回のみ、~10秒
./asoview-c   # 起動
```

```
[asoview-c] Listening on http://0.0.0.0:3001
```

これだけ。`node_modules/` なし。`pip install` なし。Docker 不要。

```bash
curl http://localhost:3001/api/v1/plans | jq '.plans[0]'
```

---

## 何が嬉しいのか

### デプロイが「バイナリを置く」で終わる

```bash
scp asoview-c user@server:/opt/app/
ssh user@server '/opt/app/asoview-c'
```

以上。ランタイムもパッケージマネージャも不要。バイナリ **285KB**、起動 **<10ms**。

### メモリが笑えるくらい少ない

| サーバー | アイドル時メモリ |
|---|---|
| Node.js (Express) | ~60MB |
| Python (FastAPI) | ~80MB |
| Go (gin) | ~15MB |
| **asoview-c** | **~3MB** |

$5/月 の VPS で本番稼働する。

### 依存がゼロ

`deps/` に mongoose・cJSON を同梱済み。システムに必要なのは `libsqlite3` と `libcurl` だけ。
CVE が出るたびに `npm audit fix` を回す生活から解放される。

---

## 本番に必要なものは全部ある

| 機能 | 状態 |
|---|---|
| JWT HS256 認証（access 1h / refresh 14d 分離・ローテーション）| ✅ |
| PBKDF2-SHA256 パスワードハッシュ | ✅ |
| IP ベースレート制限（in-memory、500/60 req/min）| ✅ |
| Stripe PaymentIntent + Webhook 署名検証 | ✅ |
| キャンセル時 Stripe 自動返金 | ✅ |
| Resend トランザクションメール | ✅ |
| パスワードリセット（1時間トークン、使い捨て）| ✅ |
| CORS プリフライト | ✅ |
| SQLite3 WAL + レビュー統計トリガー | ✅ |
| ソフトデリート（プラン）| ✅ |
| LIKE インジェクション対策 | ✅ |
| Webhook リプレイ攻撃防止（±5分タイムスタンプ）| ✅ |
| アウトバウンド Webhook HMAC-SHA256 署名 | ✅ |
| 管理者 API（X-Admin-Key 定数時間比較）| ✅ |
| 管理者 TOTP 2FA | ✅ |
| 管理者 Web UI（全 CRUD）| ✅ |
| ユーザー操作監査ログ | ✅ |
| スキーママイグレーション（自動適用・冪等）| ✅ |
| DB インデックス最適化（8本）| ✅ |
| systemd socket activation（ゼロダウンタイム再起動）| ✅ |
| マルチテナント（X-Tenant-ID ヘッダー）| ✅ |
| HSTS（HTTP Strict Transport Security）| ✅ |
| OpenAPI 3.1.0 仕様書 | ✅ |
| 統合テスト 85 ケース | ✅ |

---

## API 全エンドポイント

### 公開

```
GET  /api/v1/health
GET  /api/v1/areas
GET  /api/v1/categories
GET  /api/v1/venues[?area_id&limit&offset]
GET  /api/v1/venues/:id
GET  /api/v1/venues/:id/plans
GET  /api/v1/plans[?category_id&area_id&date&adults&page&limit]
GET  /api/v1/plans/:id
GET  /api/v1/plans/:id/schedules
GET  /api/v1/plans/:id/reviews
GET  /api/v1/search[?q&category_id&area_id]
```

### 認証・ユーザー

```
POST  /api/v1/users                    # 登録
POST  /api/v1/auth/login               # JWT 取得（2FA有効時は temp_token を返す）
PATCH /api/v1/auth/change-password     # パスワード変更（JWT）
POST  /api/v1/auth/forgot-password     # リセットトークン発行 → メール送信
POST  /api/v1/auth/reset-password      # リセット実行
POST  /api/v1/auth/refresh             # JWTリフレッシュ
POST  /api/v1/auth/logout              # ログアウト（JTI無効化）
GET   /api/v1/users/:id
PATCH /api/v1/users/:id                # 更新（JWT、本人のみ）
GET   /api/v1/users/:id/bookings       # 予約履歴（JWT）
GET   /api/v1/users/:id/bookmarks      # ブックマーク（JWT）
```

### 2FA TOTP（JWT 必須）

```
POST /api/v1/auth/2fa/setup    # シークレット生成・otpauth:// URI 返却
POST /api/v1/auth/2fa/enable   # TOTPコード確認して2FAを有効化
POST /api/v1/auth/2fa/verify   # ログイン後のTOTP検証（temp_token → JWT）
```

### 予約・レビュー・ブックマーク（JWT 必須）

```
POST   /api/v1/bookings
GET    /api/v1/bookings/:id
PATCH  /api/v1/bookings/:id/cancel      # Stripe 自動返金
GET    /api/v1/bookings/:id/ical        # iCal エクスポート（RFC 5545）
POST   /api/v1/reviews                  # 予約済みユーザーのみ
DELETE /api/v1/reviews/:id              # 本人のみ削除
POST   /api/v1/bookmarks
DELETE /api/v1/bookmarks/:plan_id
```

### クーポン

```
GET /api/v1/coupons/:code              # クーポン検証（公開）
```

### Stripe

```
POST /api/v1/webhooks/stripe           # HMAC 署名検証済み
POST /api/v1/checkout/session          # Checkout Session 作成（JWT）
```

### 管理（X-Admin-Key）

> **TOTP 有効化済みの場合は `X-Admin-TOTP: <6桁>` ヘッダも必須。**  
> 初期セットアップ: `GET /api/v1/admin/2fa/setup` で otpauth:// URI を取得 → 認証アプリで登録 → `.env` に `ADMIN_TOTP_SECRET=<secret>` を追加して再起動。

```
GET    /api/v1/admin/2fa/setup                 # 管理者 TOTP セットアップ（初回のみ）

GET|POST         /api/v1/admin/venues
PATCH|DELETE     /api/v1/admin/venues/:id
GET|POST         /api/v1/admin/plans
PATCH|DELETE     /api/v1/admin/plans/:id
PUT              /api/v1/admin/plans/:id/prices
GET|POST         /api/v1/admin/plans/:id/images   # プラン画像 CRUD
DELETE           /api/v1/admin/plan-images/:id
POST             /api/v1/admin/plans/:id/schedules
POST             /api/v1/admin/plans/:id/schedules/bulk  # 一括スケジュール生成
PATCH|DELETE     /api/v1/admin/schedules/:id
GET              /api/v1/admin/bookings[?plan_id&user_id&status&date]
POST             /api/v1/admin/bookings/:id/refund       # Stripe 返金
GET              /api/v1/admin/reviews[?plan_id&rating]
DELETE           /api/v1/admin/reviews/:id
GET              /api/v1/admin/users[?email]
GET              /api/v1/admin/reports/sales[?from&to]   # 売上 CSV ダウンロード
GET              /api/v1/admin/backup                    # SQLite バックアップ
GET|POST         /api/v1/admin/coupons                   # クーポン CRUD
DELETE           /api/v1/admin/coupons/:id
GET|POST         /api/v1/admin/webhooks                  # Webhook エンドポイント CRUD
DELETE           /api/v1/admin/webhooks/:id
GET              /api/v1/admin/dashboard
GET              /api/v1/admin/audit-logs[?actor&action&limit]
GET|POST         /api/v1/admin/tenants
GET|PATCH|DELETE /api/v1/admin/tenants/:id
```

---

## 移行手順（30 分で終わる）

### 1. バイナリを置く

```bash
make release
scp asoview-c user@server:/opt/asoview/
```

### 2. 環境変数を設定する

```bash
# /opt/asoview/.env
JWT_SECRET=$(openssl rand -hex 32)
ADMIN_KEY=$(openssl rand -hex 24)
DATABASE_URL=/data/asoview.db

# 管理者 2FA（推奨）
# 1. curl -H "X-Admin-Key: $ADMIN_KEY" http://localhost:3001/api/v1/admin/2fa/setup
# 2. 返ってきた totp_secret を下記に設定して再起動
# ADMIN_TOTP_SECRET=<totp_secret>

# メール送信
RESEND_API_KEY=re_xxxxx
RESEND_FROM=info@yourdomain.com
FRONTEND_URL=https://yourdomain.com

# Stripe 決済
STRIPE_SECRET_KEY=sk_live_xxxxx
STRIPE_WEBHOOK_SECRET=whsec_xxxxx

# Google OAuth（ソーシャルログイン、任意）
# 1. https://console.cloud.google.com → 認証情報 → OAuth 2.0 クライアントID を作成
# 2. リダイレクト URI に https://yourdomain.com/auth/google/callback を追加
GOOGLE_CLIENT_ID=<your_client_id>.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=<your_client_secret>
GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/google/callback
```

### 3. systemd に登録する

```ini
# /etc/systemd/system/asoview.service
[Unit]
After=network.target

[Service]
EnvironmentFile=/opt/asoview/.env
ExecStart=/opt/asoview/asoview-c
Restart=on-failure
User=www-data

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now asoview
curl http://localhost:3001/api/v1/health
# {"status":"ok","db":"ok"}
```

### 4. Nginx で TLS を終端する

```nginx
location / {
    proxy_pass http://127.0.0.1:3001;
}
```

詳細は [docs/deployment.md](docs/deployment.md) を参照。

---

## Docker でも動く

```bash
docker compose up -d
```

`docker-compose.yml` にヘルスチェック付きで同梱済み。

---

## テストを実行する

```bash
make test
```

```
  PASS test_create_user
  PASS test_login
  PASS test_create_booking
  PASS test_stripe_webhook
  PASS test_forgot_reset_password
  PASS test_delete_review
  PASS test_admin_update_schedule
  ...
=== 結果: 69 passed, 0 failed ===
```

テストはバイナリを自動起動して実際の HTTP リクエストを投げる統合テスト。モックなし。

---

## アーキテクチャ

```
┌──────────────────────────────────────────────────────┐
│                      asoview-c                       │
│                                                      │
│  event_handler()                                     │
│      │                                               │
│      ├─ rate_check()      512-bucket hash, in-memory │
│      │                                               │
│      ├─ handlers.c        公開 API                   │
│      ├─ admin.c           管理 API (X-Admin-Key)     │
│      ├─ stripe.c          決済 + Webhook 署名検証    │
│      └─ mailer.c          Resend メール送信          │
│                                                      │
│  SQLite3 WAL                                         │
│  ├─ venues / plans / schedules                       │
│  ├─ bookings / booking_participants                  │
│  ├─ users / reviews / bookmarks                      │
│  └─ password_reset_tokens                            │
└──────────────────────────────────────────────────────┘
```

**ルーティング**: `strcmp` + `sscanf`。フレームワークゼロ。  
**スレッド**: シングルスレッドイベントループ（mongoose）。ロック不要。  
**価格計算**: サーバー側のみ。クライアントから金額を渡せない設計。

---

## シードデータ

初回起動時に自動投入される。

| | |
|---|---|
| 会場 | 20（全国、実在モデル）|
| プラン | 42（ダイビング、陶芸、料理、忍者体験 etc.）|
| スケジュール | 300+（2026年4〜6月）|
| レビュー | 30件 |

---

## ファイル構成

```
src/
  main.c          イベントループ・ルーティング
  handlers.c/h    公開 API（予約・レビュー・ブックマーク）
  admin.c/h       管理 API
  stripe.c/h      Stripe 連携・返金
  mailer.c/h      Resend メール
  rate_limit.c/h  IP レート制限
  db.c/h          SQLite 初期化
  seed.c/h        シードデータ
  utils.c/h       JWT / PBKDF2 / UUID / base64url
deps/
  mongoose.c/h    HTTP サーバー（同梱）
  cJSON.c/h       JSON（同梱）
docs/
  deployment.md   本番構成（systemd/Nginx/Litestream）
  email-setup.md  Resend セットアップ
  stripe-setup.md Stripe フロー・テスト方法
tests/
  test_api.c      統合テスト 56 ケース
openapi.yaml      OpenAPI 3.1.0 全エンドポイント定義
docker-compose.yml
Makefile
Dockerfile
```

---

## ドキュメント

- [本番デプロイ](docs/deployment.md) — systemd / Nginx / Litestream バックアップ
- [メール設定](docs/email-setup.md) — Resend API・開発モードでの動作
- [Stripe 設定](docs/stripe-setup.md) — 決済フロー・ローカルテスト

---

## License

MIT
