# asoview-c

**Node.js/Python サーバーを捨てて、285KB のシングルバイナリに移行する話。**

[![Tests](https://img.shields.io/badge/tests-69%2F69%20pass-brightgreen)](tests/test_api.c)
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
| JWT HS256 認証 | ✅ |
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
| 管理者 API（X-Admin-Key 定数時間比較）| ✅ |
| OpenAPI 3.1.0 仕様書 | ✅ |
| 統合テスト 56 ケース | ✅ |

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
POST  /api/v1/auth/login               # JWT 取得
PATCH /api/v1/auth/change-password     # パスワード変更（JWT）
POST  /api/v1/auth/forgot-password     # リセットトークン発行 → メール送信
POST  /api/v1/auth/reset-password      # リセット実行
GET   /api/v1/users/:id
PATCH /api/v1/users/:id                # 更新（JWT、本人のみ）
GET   /api/v1/users/:id/bookings       # 予約履歴（JWT）
GET   /api/v1/users/:id/bookmarks      # ブックマーク（JWT）
```

### 予約・レビュー・ブックマーク（JWT 必須）

```
POST  /api/v1/bookings
GET   /api/v1/bookings/:id
PATCH /api/v1/bookings/:id/cancel      # Stripe 自動返金
POST  /api/v1/reviews                  # 予約済みユーザーのみ
DELETE /api/v1/reviews/:id             # 本人のみ削除
POST  /api/v1/bookmarks
DELETE /api/v1/bookmarks/:plan_id
```

### Stripe

```
POST /api/v1/webhooks/stripe           # HMAC 署名検証済み
```

### 管理（X-Admin-Key）

```
GET|POST         /api/v1/admin/venues
PATCH|DELETE     /api/v1/admin/venues/:id
GET|POST         /api/v1/admin/plans
PATCH|DELETE     /api/v1/admin/plans/:id
PUT              /api/v1/admin/plans/:id/prices
POST             /api/v1/admin/plans/:id/schedules
PATCH|DELETE     /api/v1/admin/schedules/:id
GET              /api/v1/admin/bookings[?plan_id&user_id&status&date]
GET              /api/v1/admin/reviews[?plan_id&rating]
DELETE           /api/v1/admin/reviews/:id
GET              /api/v1/admin/users[?email]
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

# オプション（未設定でも動く）
RESEND_API_KEY=re_xxxxx
RESEND_FROM=info@yourdomain.com
FRONTEND_URL=https://yourdomain.com
STRIPE_SECRET_KEY=<your_stripe_secret_key>
STRIPE_WEBHOOK_SECRET=<your_webhook_signing_secret>
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
