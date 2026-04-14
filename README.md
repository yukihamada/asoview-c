# asoview-c

> 体験・アクティビティ予約サービスの REST API — C11 シングルバイナリ

![Language](https://img.shields.io/badge/language-C11-blue)
![Tests](https://img.shields.io/badge/tests-38%2F38%20pass-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

[asoview.com](https://www.asoview.com) をモデルにした予約サービスの REST API サーバー。  
**C11 + mongoose + SQLite3 のみ**で構築したシングルバイナリ。外部ランタイム・フレームワーク不要。

---

## 特徴

| | |
|---|---|
| **Zero dependencies** | mongoose・cJSON・SQLite3 をすべて `deps/` に同梱。`make` 一発でビルド完了 |
| **JWT HS256** | CommonCrypto の `CCHmac` を使った HMAC-SHA256 スクラッチ実装 |
| **サーバー側価格計算** | `plan_prices` テーブルを参照。クライアントが価格を偽装できない |
| **SQLite3 WAL** | 組み込みDB、トリガーでレビュー統計（平均・件数）を自動更新 |
| **ソフトデリート** | プランは `is_active=0` で論理削除。履歴・予約データを保持 |
| **LIKE インジェクション対策** | `escape_like()` + `ESCAPE '\\'` でクエリを安全に処理 |
| **実データ収録** | asoview.com 由来の 12 会場・22 プランをシードデータとして収録 |

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
curl http://localhost:3001/api/v1/plans | jq '.[0]'
```

### テスト

```bash
make test
# === 結果: 38 passed, 0 failed ===
```

---

## アーキテクチャ

```
Client HTTP
    │
    ▼
event_handler()          ← mongoose イベントループ (main.c)
    │
    ├─ handle_*()        ← 公開 API ハンドラ (handlers.c)
    ├─ handle_admin_*()  ← 管理 API ハンドラ (admin.c)
    │
    ▼
SQLite3 (WAL)
    ├─ venues / plans / plan_prices
    ├─ schedules / bookings
    ├─ users / reviews
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
| `GET` | `/api/v1/venues` | 会場一覧 |
| `GET` | `/api/v1/venues/:id` | 会場詳細 |
| `GET` | `/api/v1/venues/:id/plans` | 会場のプラン一覧 |
| `GET` | `/api/v1/plans` | プラン一覧 |
| `GET` | `/api/v1/plans/:id` | プラン詳細（価格込み） |
| `GET` | `/api/v1/plans/:id/schedules` | スケジュール一覧 |
| `GET` | `/api/v1/plans/:id/reviews` | レビュー一覧 |
| `GET` | `/api/v1/search` | キーワード・エリア・カテゴリ検索 |

`GET /api/v1/plans` のクエリパラメータ:

| パラメータ | 例 | 説明 |
|---|---|---|
| `category_id` | `1` | カテゴリ絞り込み |
| `area_id` | `11` | エリア絞り込み |
| `date` | `2026-04-20` | 空きスケジュールがある日付 |
| `adults` | `2` | 参加人数（空き容量チェック） |

### 認証

| Method | Path | 説明 |
|--------|------|------|
| `POST` | `/api/v1/users` | ユーザー登録 |
| `POST` | `/api/v1/auth/login` | ログイン → JWT 取得 |
| `GET` | `/api/v1/users/:id` | プロフィール取得 |
| `PATCH` | `/api/v1/users/:id` | プロフィール更新（JWT 必須） |

### 予約（`Authorization: Bearer <token>` 必須）

| Method | Path | 説明 |
|--------|------|------|
| `POST` | `/api/v1/bookings` | 予約作成 |
| `GET` | `/api/v1/bookings/:id` | 予約詳細 |
| `PATCH` | `/api/v1/bookings/:id/cancel` | キャンセル |
| `GET` | `/api/v1/users/:id/bookings` | ユーザーの予約一覧 |
| `POST` | `/api/v1/reviews` | レビュー投稿 |

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
  -d '{"plan_id":1,"schedule_id":1,"adults":2}' | jq

# 5. レビュー投稿
curl -s -X POST http://localhost:3001/api/v1/reviews \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"plan_id":1,"rating":5,"comment":"最高の体験でした！"}' | jq
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
  -d '{"prices":[{"participant_type":"adult","price":9800}]}' | jq
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

---

## ファイル構成

```
asoview-c/
├── src/
│   ├── main.c          # イベントループ・ルーティング
│   ├── handlers.c/h    # 公開 API ハンドラ
│   ├── admin.c/h       # 管理 API ハンドラ
│   ├── db.c/h          # SQLite 初期化・スキーマ
│   ├── seed.c/h        # シードデータ（実データ）
│   └── utils.c/h       # JWT / base64url / PBKDF2
├── deps/
│   ├── mongoose.c/h    # HTTP サーバー
│   └── cJSON.c/h       # JSON
├── tests/
│   └── test_api.c      # 統合テスト (38 ケース)
├── migrations/
│   └── schema.sql      # DB スキーマ
└── Makefile
```

---

## シードデータ（asoview.com 実データ）

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

---

## 環境変数

| 変数 | デフォルト | 説明 |
|---|---|---|
| `PORT` | `3001` | リッスンポート |
| `DATABASE_URL` | `asoview.db` | SQLite DB パス |
| `JWT_SECRET` | `dev-secret` | JWT 署名シークレット（本番は変更必須） |
| `ADMIN_KEY` | `asoview-admin-dev` | 管理 API キー（本番は変更必須） |

```bash
PORT=8080 JWT_SECRET=my-secret ADMIN_KEY=my-admin-key ./asoview-c
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

**LIKE インジェクション対策**  
`escape_like()` で `%` / `_` / `\` をエスケープし、SQL に `ESCAPE '\\'` 句を付与。

**ソフトデリート**  
プランは `DELETE` せず `is_active=0` に変更。会場削除時は非アクティブプランの依存行（価格・スケジュール・レビュー）をカスケード削除してから物理削除。

---

## License

MIT
