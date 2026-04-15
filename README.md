# asoview-c

> 体験・アクティビティ予約サービスの REST API — C11 シングルバイナリ

![Language](https://img.shields.io/badge/language-C11-blue)
![Tests](https://img.shields.io/badge/tests-56%2F56%20pass-brightgreen)
![CI](https://github.com/yukihamada/asoview-c/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

[asoview.com](https://www.asoview.com) をモデルにした予約サービスの REST API サーバー。  
**C11 + mongoose + SQLite3 のみ**で構築したシングルバイナリ。外部ランタイム・フレームワーク不要。

---

## 特徴

| | |
|---|---|
| **Zero dependencies** | mongoose・cJSON・SQLite3 を `deps/` に同梱。`make` 一発でビルド完了 |
| **JWT HS256** | CommonCrypto の `CCHmac` を使った HMAC-SHA256 スクラッチ実装 |
| **サーバー側価格計算** | `plan_prices` テーブルを参照。クライアントが価格を偽装できない |
| **SQLite3 WAL** | 組み込みDB、トリガーでレビュー統計（平均・件数）を自動更新 |
| **ソフトデリート** | プランは `is_active=0` で論理削除。履歴・予約データを保持 |
| **Stripe 決済** | PaymentIntent 作成 + Webhook 署名検証 + キャンセル時自動返金 |
| **メール送信** | Resend API 経由でトランザクションメール（予約確定・キャンセル・パスワードリセット）|
| **IP レート制限** | 一般 500 req/min・認証系 60 req/min per IP（in-memory ハッシュテーブル）|
| **ブックマーク** | プランをお気に入り保存（JWT 認証必須） |
| **豊富なシードデータ** | 20 会場・42 プラン・300+ スケジュール（2026年4〜6月）・30 件レビュー |
| **定数時間比較** | ADMIN_KEY はタイミング攻撃対策済みの定数時間比較 |
| **CORS** | OPTIONS プリフライト対応（`Access-Control-Allow-*` ヘッダー付与）|
| **パスワードリセット** | 1 時間有効トークン発行 → リセット実行（使い捨て・期限切れ検証）|
| **OpenAPI 3.1.0** | `openapi.yaml` に全エンドポイントのスキーマ・セキュリティ定義 |
| **CI / Docker** | GitHub Actions + Dockerfile + docker-compose.yml 付属 |

---

## クイックスタート

```bash
git clone https://github.com/yukihamada/asoview-c
cd asoview-c
make
./asoview-c
# → http://localhost:3001
```

```bash
# 動作確認
curl http://localhost:3001/api/v1/health
# {"status":"ok","db":"ok"}

# プラン一覧
curl http://localhost:3001/api/v1/plans | jq '.plans[0].title'
```

### Docker

```bash
docker build -t asoview-c .
docker run -p 3001:3001 -v $(pwd)/data:/data --env-file .env asoview-c
```

### docker-compose（推奨）

```bash
cp .env.example .env   # 環境変数を設定
docker compose up -d
```

### テスト

```bash
make test
# === 結果: 56 passed, 0 failed ===
```

---

## アーキテクチャ

```
Client HTTP
    │
    ▼
event_handler()          ← rate_check() → 429 if exceeded
    │
    ├─ handle_*()        ← 公開 API ハンドラ (handlers.c)
    ├─ handle_admin_*()  ← 管理 API ハンドラ (admin.c)
    ├─ handle_stripe_*() ← Stripe Webhook (stripe.c)
    │
    ▼
SQLite3 (WAL)
    ├─ venues / plans / plan_prices
    ├─ schedules / bookings / booking_participants
    ├─ users / reviews / bookmarks
    ├─ password_reset_tokens
    └─ areas / categories
```

**ルーティング**は `strcmp` + `sscanf` で実装。UUID は `%36[^/]`（スラッシュを含まない36文字）で抽出。フレームワーク依存ゼロ。

---

## API リファレンス

完全な仕様は `openapi.yaml` を参照。

### 公開エンドポイント

| Method | Path | 説明 |
|--------|------|------|
| `GET` | `/api/v1/health` | ヘルスチェック |
| `GET` | `/api/v1/areas` | エリア一覧 |
| `GET` | `/api/v1/categories` | カテゴリ一覧 |
| `GET` | `/api/v1/venues` | 会場一覧（ページネーション対応）|
| `GET` | `/api/v1/venues/:id` | 会場詳細 |
| `GET` | `/api/v1/venues/:id/plans` | 会場のプラン一覧 |
| `GET` | `/api/v1/plans` | プラン一覧（ページネーション対応）|
| `GET` | `/api/v1/plans/:id` | プラン詳細（価格込み）|
| `GET` | `/api/v1/plans/:id/schedules` | スケジュール一覧 |
| `GET` | `/api/v1/plans/:id/reviews` | レビュー一覧 |
| `GET` | `/api/v1/search` | キーワード・エリア・カテゴリ検索 |

### 認証

| Method | Path | 説明 |
|--------|------|------|
| `POST` | `/api/v1/users` | ユーザー登録 |
| `POST` | `/api/v1/auth/login` | ログイン → JWT 取得 |
| `PATCH` | `/api/v1/auth/change-password` | パスワード変更（JWT 必須）|
| `POST` | `/api/v1/auth/forgot-password` | パスワードリセットトークン発行（→ Resend メール送信）|
| `POST` | `/api/v1/auth/reset-password` | パスワードリセット実行 |
| `GET` | `/api/v1/users/:id` | プロフィール取得 |
| `PATCH` | `/api/v1/users/:id` | プロフィール更新（JWT 必須）|

### 予約（`Authorization: Bearer <token>` 必須）

| Method | Path | 説明 |
|--------|------|------|
| `POST` | `/api/v1/bookings` | 予約作成（Stripe or 即時確定）|
| `GET` | `/api/v1/bookings/:id` | 予約詳細 |
| `PATCH` | `/api/v1/bookings/:id/cancel` | キャンセル（Stripe 自動返金）|
| `GET` | `/api/v1/users/:id/bookings` | ユーザーの予約一覧 |

### レビュー・ブックマーク（JWT 必須）

| Method | Path | 説明 |
|--------|------|------|
| `POST` | `/api/v1/reviews` | レビュー投稿（予約済みユーザーのみ）|
| `DELETE` | `/api/v1/reviews/:id` | 自分のレビュー削除 |
| `POST` | `/api/v1/bookmarks` | プランをブックマーク |
| `DELETE` | `/api/v1/bookmarks/:plan_id` | ブックマーク削除 |
| `GET` | `/api/v1/users/:id/bookmarks` | ユーザーのブックマーク一覧 |

### Stripe Webhook

| Method | Path | 説明 |
|--------|------|------|
| `POST` | `/api/v1/webhooks/stripe` | Stripe イベント受信（署名検証）|

### 管理（`X-Admin-Key` ヘッダー必須）

| Method | Path | 説明 |
|--------|------|------|
| `GET` | `/api/v1/admin/venues` | 会場一覧 |
| `POST` | `/api/v1/admin/venues` | 会場作成 |
| `PATCH` | `/api/v1/admin/venues/:id` | 会場更新 |
| `DELETE` | `/api/v1/admin/venues/:id` | 会場削除 |
| `GET` | `/api/v1/admin/plans` | プラン一覧 |
| `POST` | `/api/v1/admin/plans` | プラン作成 |
| `PATCH` | `/api/v1/admin/plans/:id` | プラン更新 |
| `DELETE` | `/api/v1/admin/plans/:id` | プラン削除（ソフトデリート）|
| `PUT` | `/api/v1/admin/plans/:id/prices` | 価格設定 |
| `POST` | `/api/v1/admin/plans/:id/schedules` | スケジュール作成 |
| `PATCH` | `/api/v1/admin/schedules/:id` | スケジュール更新 |
| `DELETE` | `/api/v1/admin/schedules/:id` | スケジュール削除 |
| `GET` | `/api/v1/admin/bookings` | 予約一覧（フィルタ・ページネーション）|
| `GET` | `/api/v1/admin/reviews` | レビュー一覧（フィルタ・ページネーション）|
| `DELETE` | `/api/v1/admin/reviews/:id` | レビュー削除（管理者）|
| `GET` | `/api/v1/admin/users` | ユーザー一覧（メール検索）|

---

## 使用例

### ユーザー登録 → ログイン → 予約

```bash
# 1. ユーザー登録
curl -s -X POST http://localhost:3001/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"pass1234","name":"Alice"}' | jq

# 2. ログイン
TOKEN=$(curl -s -X POST http://localhost:3001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"pass1234"}' | jq -r '.token')

# 3. プランのスケジュール確認
curl -s "http://localhost:3001/api/v1/plans/1/schedules" | jq

# 4. 予約作成（価格はサーバーが計算）
curl -s -X POST http://localhost:3001/api/v1/bookings \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"plan_id":1,"schedule_id":1,"participants":[{"participant_type":"adult","count":2}]}' | jq

# 5. レビュー投稿
curl -s -X POST http://localhost:3001/api/v1/reviews \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"plan_id":1,"rating":5,"comment":"最高の体験でした！"}' | jq
```

### 管理 API

```bash
ADMIN="X-Admin-Key: asoview-admin-dev"

# 予約一覧（ステータス=confirmed）
curl -s "http://localhost:3001/api/v1/admin/bookings?status=confirmed" \
  -H "$ADMIN" | jq '.total'

# スケジュール更新（容量変更）
curl -s -X PATCH http://localhost:3001/api/v1/admin/schedules/1 \
  -H "Content-Type: application/json" \
  -H "$ADMIN" \
  -d '{"capacity":20}' | jq

# プランに価格設定
curl -s -X PUT http://localhost:3001/api/v1/admin/plans/1/prices \
  -H "Content-Type: application/json" \
  -H "$ADMIN" \
  -d '[{"participant_type":"adult","label":"大人","price":9800}]' | jq
```

---

## 技術スタック

| 役割 | ライブラリ | バージョン |
|---|---|---|
| HTTP サーバー | [mongoose](https://github.com/cesanta/mongoose) | 7.15 |
| JSON | [cJSON](https://github.com/DaveGamble/cJSON) | 1.7.18 |
| DB | SQLite3 (WAL mode) | システム同梱 |
| 認証 | JWT HS256 (CommonCrypto) | スクラッチ実装 |
| パスワード | PBKDF2-SHA256 (CommonCrypto) | スクラッチ実装 |
| 決済 | Stripe PaymentIntent + Webhook | libcurl + CommonCrypto |
| メール | Resend REST API | libcurl |

---

## ファイル構成

```
asoview-c/
├── src/
│   ├── main.c          # イベントループ・ルーティング・レート制限
│   ├── handlers.c/h    # 公開 API ハンドラ（予約・レビュー・ブックマーク等）
│   ├── admin.c/h       # 管理 API ハンドラ
│   ├── stripe.c/h      # Stripe PaymentIntent + Webhook 署名検証 + 返金
│   ├── mailer.c/h      # Resend API メール送信
│   ├── rate_limit.c/h  # IP ベースレート制限（512バケット ハッシュテーブル）
│   ├── db.c/h          # SQLite 初期化・スキーマ
│   ├── seed.c/h        # シードデータ（20会場・42プラン・300+スケジュール）
│   └── utils.c/h       # JWT / base64url / PBKDF2 / UUID
├── deps/
│   ├── mongoose.c/h    # HTTP サーバー
│   └── cJSON.c/h       # JSON
├── tests/
│   └── test_api.c      # 統合テスト（56 ケース）
├── migrations/
│   └── schema.sql      # DB スキーマ
├── docs/
│   ├── deployment.md   # 本番デプロイ手順（systemd / Nginx / Litestream）
│   ├── email-setup.md  # Resend メール設定
│   └── stripe-setup.md # Stripe 設定・テスト方法
├── .github/
│   └── workflows/
│       └── ci.yml      # GitHub Actions CI
├── openapi.yaml        # OpenAPI 3.1.0 仕様書（全エンドポイント）
├── Dockerfile
├── docker-compose.yml
└── Makefile
```

---

## シードデータ（実データ準拠）

**20 会場 × 42 プラン × 300+ スケジュール（2026年4〜6月）**

| 会場 | エリア | カテゴリ |
|---|---|---|
| 沖縄マリンクラブ OCEANUS | 沖縄県 | ダイビング・シュノーケリング |
| 堀越陶房 | 大阪府 | 陶芸 |
| 瑞光窯 京都清水店 | 京都府 | 陶芸 |
| 比謝川カヤック | 沖縄県 | カヤック・SUP |
| アカネス京都 | 京都府 | ハンドメイド |
| 北海道ネイチャーガイド YAMA TO KAWA | 北海道 | カヌー |
| 東京忍者体験道場 NINJA TRICK | 東京都 | 忍者体験 |
| 京都・舞妓体験処「雅」 | 京都府 | 着物・浴衣 |
| 朝霧高原パラグライダースクール | 山梨県 | パラグライダー |
| なにわ料理アカデミー東京 | 東京都 | 料理教室 |
| （他 10 会場 …）| | |

---

## セキュリティ

| 項目 | 実装 |
|---|---|
| JWT 署名 | HMAC-SHA256（CommonCrypto）、HS256 スクラッチ実装 |
| パスワード | PBKDF2-SHA256、10,000 イテレーション |
| ADMIN_KEY 検証 | 定数時間比較（タイミング攻撃対策）|
| Webhook 署名 | HMAC-SHA256 + タイムスタンプ ±5 分（リプレイ攻撃防止）|
| レート制限 | 一般 500 req/min、認証系 60 req/min per IP |
| LIKE インジェクション | `escape_like()` + `ESCAPE '\\'` |
| note 長さ上限 | 1,000 文字（DoS 防止）|
| TLS 検証 | libcurl の証明書検証を有効のまま維持 |
| メール送信 | RESEND_API_KEY 未設定時はスキップ、dev モード時のみトークン返却 |

---

## 環境変数

| 変数 | デフォルト | 説明 |
|---|---|---|
| `PORT` | `3001` | リッスンポート |
| `DATABASE_URL` | `asoview.db` | SQLite DB パス |
| `JWT_SECRET` | `asoview-jwt-secret-dev` | JWT 署名シークレット（本番は 32 文字以上）|
| `ADMIN_KEY` | `asoview-admin-dev` | 管理 API キー |
| `RESEND_API_KEY` | — | Resend メール API キー（未設定時はメール送信スキップ）|
| `RESEND_FROM` | `noreply@example.com` | 送信元メールアドレス |
| `FRONTEND_URL` | `http://localhost:3000` | パスワードリセットリンクのベース URL |
| `STRIPE_SECRET_KEY` | — | Stripe 秘密鍵（未設定時は決済スキップ）|
| `STRIPE_WEBHOOK_SECRET` | — | Stripe Webhook 署名シークレット |

---

## 実装のポイント

**JWT HS256**  
`header.payload.signature` を base64url エンコード。CommonCrypto の `CCHmac` で署名を計算。外部ライブラリなし。

**ルーティング**  
`strcmp` / `sscanf` + `%36[^/]` でパスを解析。`/bookings/:id` と `/bookings/:id/cancel` の区別はマッチ後に suffix を比較。

**価格計算**  
クライアントから `total_price` を受け付けない。`plan_prices` テーブルを参照してサーバー側で計算・記録。

**容量チェック**  
`capacity - booked_count >= requested` を SQLite 側でアトミックに検証。超過は 409 を返す。

**Stripe 連携**  
`STRIPE_SECRET_KEY` が未設定の場合は `status='confirmed'` で即時確定。設定時は `pending_payment` → Webhook で `confirmed` / `cancelled` に遷移。キャンセル時は自動返金。

**メール**  
libcurl で Resend REST API に POST。mongoose 単一スレッドなので同期呼び出し（~100-500ms ブロック）。

**レート制限**  
512 バケットのハッシュテーブル（in-memory）。mongoose 単一スレッドなのでミューテックス不要。ウィンドウ期限切れでバケットをリセット。

**LIKE インジェクション対策**  
`escape_like()` で `%` / `_` / `\` をエスケープし、SQL に `ESCAPE '\\'` 句を付与。

**ソフトデリート**  
プランは `DELETE` せず `is_active=0` に変更。会場削除時は非アクティブプランの依存行をカスケード削除してから物理削除。

---

## ドキュメント

- [本番デプロイ手順](docs/deployment.md) — systemd / Nginx / Litestream
- [メール設定](docs/email-setup.md) — Resend API セットアップ
- [Stripe 設定](docs/stripe-setup.md) — 決済フロー・テスト方法

---

## License

MIT
