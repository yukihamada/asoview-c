# asoview-c

> 体験・アクティビティ予約サービスの REST API — C11 シングルバイナリ

![Language](https://img.shields.io/badge/language-C11-blue)
![Tests](https://img.shields.io/badge/tests-41%2F41%20pass-brightgreen)
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
| **Stripe 決済** | PaymentIntent 作成 + Webhook 署名検証（HMAC-SHA256 + タイムスタンプ検証）|
| **IP レート制限** | 一般 120 req/min・認証系 10 req/min per IP（in-memory ハッシュテーブル）|
| **ブックマーク** | プランをお気に入り保存（JWT 認証必須） |
| **豊富なシードデータ** | 20 会場・42 プラン・300+ スケジュール（2026年4〜6月）・30 件レビュー |
| **定数時間比較** | ADMIN_KEY はタイミング攻撃対策済みの定数時間比較 |
| **CI / Docker** | GitHub Actions + Dockerfile 付属 |

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
# {"status":"ok"}

# プラン一覧
curl http://localhost:3001/api/v1/plans | jq '.plans[0].title'
```

### Docker

```bash
docker build -t asoview-c .
docker run -p 3001:3001 -v $(pwd)/data:/data asoview-c
```

### テスト

```bash
make test
# === 結果: 41 passed, 0 failed ===
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
    └─ areas / categories
```

**ルーティング**は `strcmp` + `sscanf` で実装。UUID は `%36[^/]`（スラッシュを含まない36文字）で抽出。フレームワーク依存ゼロ。

---

## API リファレンス

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

`GET /api/v1/plans` のクエリパラメータ:

| パラメータ | 例 | 説明 |
|---|---|---|
| `category_id` | `1` | カテゴリ絞り込み |
| `area_id` | `11` | エリア絞り込み |
| `date` | `2026-04-20` | 空きスケジュールがある日付 |
| `adults` | `2` | 参加人数（空き容量チェック）|
| `page` | `2` | ページ番号（デフォルト 1）|
| `limit` | `20` | 1ページ当たり件数（デフォルト 20）|

### 認証

| Method | Path | 説明 |
|--------|------|------|
| `POST` | `/api/v1/users` | ユーザー登録 |
| `POST` | `/api/v1/auth/login` | ログイン → JWT 取得 |
| `GET` | `/api/v1/users/:id` | プロフィール取得 |
| `PATCH` | `/api/v1/users/:id` | プロフィール更新（JWT 必須）|

### 予約（`Authorization: Bearer <token>` 必須）

| Method | Path | 説明 |
|--------|------|------|
| `POST` | `/api/v1/bookings` | 予約作成 |
| `GET` | `/api/v1/bookings/:id` | 予約詳細 |
| `PATCH` | `/api/v1/bookings/:id/cancel` | キャンセル |
| `GET` | `/api/v1/users/:id/bookings` | ユーザーの予約一覧 |
| `POST` | `/api/v1/reviews` | レビュー投稿 |

### ブックマーク（JWT 必須）

| Method | Path | 説明 |
|--------|------|------|
| `POST` | `/api/v1/bookmarks` | プランをブックマーク |
| `DELETE` | `/api/v1/bookmarks/:plan_id` | ブックマーク削除 |
| `GET` | `/api/v1/users/:id/bookmarks` | ユーザーのブックマーク一覧 |

### Stripe Webhook

| Method | Path | 説明 |
|--------|------|------|
| `POST` | `/api/v1/webhooks/stripe` | Stripe イベント受信（署名検証）|

### 管理（`X-Admin-Key` ヘッダー必須）

```
POST    /api/v1/admin/venues
PATCH   /api/v1/admin/venues/:id
DELETE  /api/v1/admin/venues/:id

POST    /api/v1/admin/plans
PATCH   /api/v1/admin/plans/:id
DELETE  /api/v1/admin/plans/:id       # ソフトデリート (is_active=0)
PUT     /api/v1/admin/plans/:id/prices

POST    /api/v1/admin/plans/:id/schedules
DELETE  /api/v1/admin/schedules/:id
```

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

# 5. ブックマーク
curl -s -X POST http://localhost:3001/api/v1/bookmarks \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"plan_id":2}' | jq

# 6. レビュー投稿
curl -s -X POST http://localhost:3001/api/v1/reviews \
  -H "Content-Type: application/json" \
  -d '{"plan_id":1,"user_id":1,"rating":5,"comment":"最高の体験でした！"}' | jq
```

### 管理 API

```bash
ADMIN="X-Admin-Key: asoview-admin-dev"

# 会場作成
curl -s -X POST http://localhost:3001/api/v1/admin/venues \
  -H "Content-Type: application/json" \
  -H "$ADMIN" \
  -d '{"name":"テスト会場","area_id":6,"address":"東京都渋谷区1-1","description":"説明"}' | jq

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

---

## ファイル構成

```
asoview-c/
├── src/
│   ├── main.c          # イベントループ・ルーティング・レート制限
│   ├── handlers.c/h    # 公開 API ハンドラ（予約・レビュー・ブックマーク等）
│   ├── admin.c/h       # 管理 API ハンドラ
│   ├── stripe.c/h      # Stripe PaymentIntent + Webhook 署名検証
│   ├── rate_limit.c/h  # IP ベースレート制限（512バケット ハッシュテーブル）
│   ├── db.c/h          # SQLite 初期化・スキーマ
│   ├── seed.c/h        # シードデータ（20会場・42プラン・300+スケジュール）
│   └── utils.c/h       # JWT / base64url / PBKDF2 / UUID
├── deps/
│   ├── mongoose.c/h    # HTTP サーバー
│   └── cJSON.c/h       # JSON
├── tests/
│   └── test_api.c      # 統合テスト（41 ケース）
├── migrations/
│   └── schema.sql      # DB スキーマ
├── .github/
│   └── workflows/
│       └── ci.yml      # GitHub Actions CI
├── Dockerfile
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
| 湘南乗馬クラブ HORSE LAND | 神奈川県 | 乗馬 |
| 能登半島アウトドアベース | 石川県 | シーカヤック・ラフティング |
| 鎌倉着物レンタル 花衣 | 神奈川県 | 着物・浴衣 |
| 東京湾クルージングクラブ | 東京都 | 観光・ツアー |
| 白馬アルプスアウトドアセンター | 長野県 | トレッキング・スキー |
| 富士山麓アドベンチャーパーク | 山梨県 | キャニオニング |
| 奈良もちいどの陶芸教室 | 奈良県 | 陶芸 |
| 博多料理道場 | 福岡県 | 料理教室 |
| 函館ガラス工芸 海の色 | 北海道 | ガラス工芸 |
| 有馬温泉 陶芸倶楽部 | 兵庫県 | 陶芸 |

---

## セキュリティ

| 項目 | 実装 |
|---|---|
| JWT 署名 | HMAC-SHA256（CommonCrypto）、HS256 スクラッチ実装 |
| パスワード | PBKDF2-SHA256、10,000 イテレーション |
| ADMIN_KEY 検証 | 定数時間比較（タイミング攻撃対策）|
| Webhook 署名 | HMAC-SHA256 + タイムスタンプ ±5 分（リプレイ攻撃防止）|
| レート制限 | 一般 120 req/min、認証系 10 req/min per IP |
| LIKE インジェクション | `escape_like()` + `ESCAPE '\\'` |
| note 長さ上限 | 1,000 文字（DoS 防止）|
| TLS 検証 | libcurl の証明書検証を有効のまま維持 |

---

## 環境変数

| 変数 | デフォルト | 説明 |
|---|---|---|
| `PORT` | `3001` | リッスンポート |
| `DATABASE_URL` | `asoview.db` | SQLite DB パス |
| `JWT_SECRET` | `asoview-jwt-secret-dev` | JWT 署名シークレット（本番は 32 文字以上）|
| `ADMIN_KEY` | `asoview-admin-dev` | 管理 API キー |
| `STRIPE_SECRET_KEY` | — | Stripe 秘密鍵（未設定時は決済スキップ）|
| `STRIPE_WEBHOOK_SECRET` | — | Stripe Webhook 署名シークレット |

```bash
PORT=8080 \
JWT_SECRET=$(openssl rand -hex 32) \
ADMIN_KEY=$(openssl rand -hex 16) \
STRIPE_SECRET_KEY=sk_live_... \
STRIPE_WEBHOOK_SECRET=whsec_... \
./asoview-c
```

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
`STRIPE_SECRET_KEY` が未設定の場合は `status='confirmed'` で即時確定。設定時は `pending_payment` → Webhook で `confirmed` / `cancelled` に遷移。

**レート制限**  
512 バケットのハッシュテーブル（in-memory）。mongoose 単一スレッドなのでミューテックス不要。ウィンドウ期限切れでバケットをリセット。

**LIKE インジェクション対策**  
`escape_like()` で `%` / `_` / `\` をエスケープし、SQL に `ESCAPE '\\'` 句を付与。

**ソフトデリート**  
プランは `DELETE` せず `is_active=0` に変更。会場削除時は非アクティブプランの依存行をカスケード削除してから物理削除。

---

## License

MIT
