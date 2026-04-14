# asoview-c — システムドキュメント

アクティビティ・体験予約サービス「あそビュー」の C 言語リファレンス実装。

---

## 目次

1. [概要](#概要)
2. [アーキテクチャ](#アーキテクチャ)
3. [ディレクトリ構成](#ディレクトリ構成)
4. [依存ライブラリ](#依存ライブラリ)
5. [ビルド・起動](#ビルド起動)
6. [DBスキーマ](#dbスキーマ)
7. [API リファレンス](#api-リファレンス)
8. [認証・セキュリティ](#認証セキュリティ)
9. [テスト](#テスト)
10. [設計メモ](#設計メモ)

---

## 概要

| 項目 | 内容 |
|---|---|
| 言語 | C11 |
| HTTP サーバー | Mongoose 7.15（シングルスレッドイベントループ） |
| JSON | cJSON 1.7.18 |
| DB | SQLite 3（WAL モード） |
| パスワード | PBKDF2-SHA256（CommonCrypto, 100,000 iterations） |
| デフォルトポート | 3001 |
| デフォルト DB | `asoview.db` |

---

## アーキテクチャ

```
┌─────────────────────────────────────────────────────────────┐
│  クライアント (HTTP)                                          │
└───────────────────────┬─────────────────────────────────────┘
                        │ TCP
┌───────────────────────▼─────────────────────────────────────┐
│  mongoose イベントループ  (main.c)                            │
│  mg_mgr_poll() — 100ms タイムアウト                           │
│                                                             │
│  event_handler()                                            │
│    URI ルーティング (strcmp / sscanf)                         │
│      └─ handlers.c の各ハンドラを呼び出す                     │
└───────────────────────┬─────────────────────────────────────┘
                        │ SQLite C API
┌───────────────────────▼─────────────────────────────────────┐
│  SQLite (asoview.db)                                        │
│  WAL + FK + busy_timeout=5000ms                             │
└─────────────────────────────────────────────────────────────┘
```

**スレッドモデル**: シングルスレッド。mongoose のイベントループが接続・I/O・タイマーをすべて処理する。SQLite アクセスもメインスレッドから直接行うため、ロック競合は起きない。

---

## ディレクトリ構成

```
asoview-c/
├── deps/               外部ライブラリ（ヘッダ + 実装を1ファイルに同梱）
│   ├── mongoose.h/.c   HTTP サーバーライブラリ
│   └── cJSON.h/.c      JSON パーサー / ビルダー
├── migrations/
│   └── schema.sql      DDL（テーブル定義・トリガー）
├── scripts/
│   └── gen_schema_embed.py  schema.sql → C 文字列リテラルに変換
├── src/
│   ├── schema_embed.h  自動生成（make schema で更新）
│   ├── db.h/.c         DB オープン・マイグレーション
│   ├── utils.h/.c      UUID 生成・パスワードハッシュ・文字列ヘルパー
│   ├── seed.h/.c       初期データ投入（起動時に1回）
│   ├── handlers.h/.c   全 REST ハンドラ実装
│   └── main.c          エントリポイント・ルーティング
├── tests/
│   └── test_api.c      統合テスト 26 本（libcurl + fork/exec）
├── Makefile
└── docs/
    └── README.md       本ドキュメント
```

---

## 依存ライブラリ

| ライブラリ | バージョン | 用途 | 取得方法 |
|---|---|---|---|
| [Mongoose](https://github.com/cesanta/mongoose) | 7.15 | HTTP サーバー | `deps/` に同梱 |
| [cJSON](https://github.com/DaveGamble/cJSON) | 1.7.18 | JSON | `deps/` に同梱 |
| SQLite3 | system | DB | システム提供 (`-lsqlite3`) |
| CommonCrypto | system (macOS) | PBKDF2 | `-framework Security -framework CoreFoundation` |
| libcurl | system | テスト専用 HTTP クライアント | `-lcurl` |

---

## ビルド・起動

### ビルド

```bash
make          # asoview-c バイナリを生成
make test     # バイナリ生成 + 統合テスト実行
make clean    # バイナリ・テスト・DB を削除
make schema   # schema.sql を src/schema_embed.h に再生成
```

### 起動

```bash
# デフォルト (DB=asoview.db, PORT=3001)
./asoview-c

# 引数で上書き
./asoview-c mydb.db 8080

# 環境変数で上書き
DATABASE_URL=mydb.db PORT=8080 ./asoview-c
```

優先順位: `argv[1]` / `argv[2]` > 環境変数 > デフォルト値

### 動作確認

```bash
curl http://localhost:3001/api/v1/health
# {"status":"ok","service":"asoview","version":"0.1.0"}
```

---

## DBスキーマ

### ER 図（概念）

```
areas ─────────┐
               ▼
categories     venues ──────┐
    │              │         │
    └──────────────▼         ▼
                plans ────► schedules
                  │              ▲
                  ▼              │
             plan_prices    bookings ──► booking_participants
                                │
                             reviews
```

### テーブル一覧

#### `areas` — 地域マスタ（階層構造）

| カラム | 型 | 説明 |
|---|---|---|
| id | INTEGER PK | |
| name | TEXT | 地域名（例: 関東、東京都） |
| name_kana | TEXT | 読み仮名 |
| parent_id | INTEGER FK | 親地域（NULL = 最上位） |
| level | INTEGER | 0=地方, 1=都道府県, 2=市区 |
| slug | TEXT UNIQUE | URL スラッグ（例: `tokyo`） |

#### `categories` — カテゴリマスタ（階層構造）

| カラム | 型 | 説明 |
|---|---|---|
| id | INTEGER PK | |
| name | TEXT | カテゴリ名（例: アウトドア、ダイビング） |
| slug | TEXT UNIQUE | URL スラッグ |
| parent_id | INTEGER FK | 親カテゴリ（NULL = 最上位） |
| icon | TEXT | 絵文字アイコン |

#### `venues` — 施設・拠点

| カラム | 型 | 説明 |
|---|---|---|
| id | INTEGER PK | |
| name | TEXT | 施設名 |
| description | TEXT | 説明文 |
| area_id | INTEGER FK | 地域 |
| address | TEXT | 住所 |
| latitude / longitude | REAL | 緯度・経度 |
| phone | TEXT | 電話番号 |
| images | TEXT | JSON 配列（画像 URL） |
| review_count / review_avg | INTEGER/REAL | トリガーで自動集計 |

#### `plans` — 体験プラン

| カラム | 型 | 説明 |
|---|---|---|
| id | INTEGER PK | |
| venue_id | INTEGER FK | 施設 |
| category_id | INTEGER FK | カテゴリ |
| title | TEXT | プラン名 |
| description | TEXT | 説明 |
| duration_minutes | INTEGER | 所要時間（分） |
| min/max_participants | INTEGER | 最小・最大人数 |
| min_age | INTEGER | 参加最低年齢 |
| images / tags | TEXT | JSON 配列 |
| is_active | INTEGER | 1=公開, 0=非公開 |

#### `plan_prices` — 価格設定

| カラム | 型 | 説明 |
|---|---|---|
| id | INTEGER PK | |
| plan_id | INTEGER FK | プラン |
| participant_type | TEXT | `adult` / `child` / `senior` |
| label | TEXT | 表示名（例: 大人（18歳以上）） |
| price | INTEGER | 単価（円） |

#### `schedules` — スケジュール

| カラム | 型 | 説明 |
|---|---|---|
| id | INTEGER PK | |
| plan_id | INTEGER FK | プラン |
| date | TEXT | 日付（YYYY-MM-DD） |
| start_time / end_time | TEXT | 開始・終了時刻（HH:MM） |
| capacity | INTEGER | 定員 |
| booked_count | INTEGER | 予約済み人数（トリガーで自動更新） |

#### `users` — ユーザー

| カラム | 型 | 説明 |
|---|---|---|
| id | INTEGER PK | |
| email | TEXT UNIQUE | |
| name | TEXT | |
| phone | TEXT | |
| password_hash | TEXT | `pbkdf2$<hex-salt>$<hex-dk>` |

#### `bookings` — 予約

| カラム | 型 | 説明 |
|---|---|---|
| id | TEXT PK | UUID v4 |
| user_id | INTEGER FK | ユーザー |
| plan_id | INTEGER FK | プラン |
| schedule_id | INTEGER FK | スケジュール |
| status | TEXT | `pending` / `confirmed` / `cancelled` |
| total_price | INTEGER | 合計金額（円） |
| note | TEXT | 備考 |

#### `booking_participants` — 予約参加者内訳

| カラム | 型 | 説明 |
|---|---|---|
| id | INTEGER PK | |
| booking_id | TEXT FK | 予約 |
| participant_type | TEXT | `adult` / `child` など |
| label | TEXT | 表示名 |
| count | INTEGER | 人数 |
| unit_price | INTEGER | 単価（確定値） |

#### `reviews` — レビュー

| カラム | 型 | 説明 |
|---|---|---|
| id | INTEGER PK | |
| booking_id | TEXT FK | 予約（任意） |
| user_id | INTEGER FK | ユーザー |
| plan_id | INTEGER FK | プラン |
| rating | INTEGER | 1〜5 |
| comment | TEXT | コメント |

### トリガー

| トリガー | タイミング | 内容 |
|---|---|---|
| `update_venue_review_stats` | `reviews` INSERT後 | 施設の `review_count` / `review_avg` を再集計 |
| `update_schedule_booked_count` | `booking_participants` INSERT後 | スケジュールの `booked_count` に人数を加算 |

---

## API リファレンス

ベース URL: `http://localhost:3001/api/v1`

すべてのレスポンスは `Content-Type: application/json`。エラーは `{"error": "<message>"}` 形式。

---

### ヘルス確認

#### `GET /health`

```json
{"status":"ok","service":"asoview","version":"0.1.0"}
```

---

### 地域

#### `GET /areas`

全地域をレベル順で返す。

```json
[
  {"id":1,"name":"関東","name_kana":"かんとう","parent_id":null,"level":0,"slug":"kanto"},
  {"id":6,"name":"東京都","name_kana":"とうきょうと","parent_id":1,"level":1,"slug":"tokyo"}
]
```

---

### カテゴリ

#### `GET /categories`

```json
[
  {"id":1,"name":"アウトドア","slug":"outdoor","parent_id":null,"icon":"🏕️"},
  {"id":6,"name":"ダイビング","slug":"diving","parent_id":1,"icon":"🤿"}
]
```

---

### 施設

#### `GET /venues`

**クエリパラメータ**

| パラメータ | 型 | 説明 |
|---|---|---|
| area_id | integer | 地域フィルタ |
| category_id | integer | カテゴリフィルタ（その施設にそのカテゴリのプランがある） |

```json
[
  {
    "id": 1,
    "name": "沖縄マリンクラブ OCEANUS",
    "description": "...",
    "area_id": 11,
    "address": "沖縄県那覇市...",
    "latitude": 26.2041,
    "longitude": 127.6792,
    "phone": "098-123-4567",
    "images": [],
    "review_count": 0,
    "review_avg": 0.0
  }
]
```

#### `GET /venues/:id`

施設詳細 + プラン一覧（価格込み）を返す。

```json
{
  "id": 1,
  "name": "沖縄マリンクラブ OCEANUS",
  "plans": [
    {
      "id": 1,
      "title": "体験ダイビング（初心者向け）",
      "prices": [
        {"participant_type":"adult","label":"大人（18歳以上）","price":15000}
      ]
    }
  ]
}
```

---

### プラン

#### `GET /plans`

**クエリパラメータ**

| パラメータ | 型 | 説明 |
|---|---|---|
| venue_id | integer | 施設フィルタ |
| category_id | integer | カテゴリフィルタ |
| area_id | integer | 地域フィルタ |
| date | string | YYYY-MM-DD — その日に空き枠があるプランのみ |
| adults | integer | 大人人数（date と組み合わせて空き枠チェック） |
| children | integer | 子供人数 |

```json
{
  "plans": [
    {
      "id": 1,
      "venue_id": 1,
      "category_id": 6,
      "title": "体験ダイビング（初心者向け）",
      "duration_minutes": 180,
      "min_participants": 1,
      "max_participants": 8,
      "min_age": 10,
      "tags": ["初心者OK","GoProレンタル無料"],
      "prices": [...]
    }
  ]
}
```

#### `GET /plans/:id`

プラン詳細 + 価格リスト。

---

### スケジュール

#### `GET /plans/:plan_id/schedules`

**クエリパラメータ**

| パラメータ | 型 | 説明 |
|---|---|---|
| date | string | YYYY-MM-DD フィルタ |

```json
[
  {
    "id": 1,
    "plan_id": 1,
    "date": "2026-04-20",
    "start_time": "09:00",
    "end_time": "12:00",
    "capacity": 8,
    "booked_count": 0,
    "available": 8
  }
]
```

---

### ユーザー

#### `POST /users` — ユーザー登録

**リクエストボディ**

```json
{
  "email": "taro@example.com",
  "name": "田中太郎",
  "phone": "090-1234-5678",
  "password": "password123"
}
```

**バリデーション**

- `email` / `name` / `password` は必須
- `password` は 8 文字以上
- メールアドレス重複時は `409 Conflict`

**レスポンス** `201 Created`

```json
{"id": 3, "email": "taro@example.com", "name": "田中太郎"}
```

---

### 認証

#### `POST /auth/login`

```json
{"email": "taro@example.com", "password": "password123"}
```

**レスポンス** `200 OK`

```json
{"user_id": 1, "name": "田中太郎", "email": "taro@example.com"}
```

> **注**: 現在はセッショントークンを発行しない（今後 JWT 追加予定）。

---

### 予約

#### `POST /bookings` — 予約作成

```json
{
  "user_id": 1,
  "plan_id": 1,
  "schedule_id": 1,
  "participants": [
    {"participant_type": "adult", "count": 2},
    {"participant_type": "child", "count": 1}
  ],
  "note": "アレルギーあり"
}
```

**バリデーション**

- `user_id` / `plan_id` / `schedule_id` / `participants` は必須
- `participants` の各エントリに `participant_type` と `count`（1以上）が必要
- 参加者合計 > スケジュールの残り枠なら `409 Conflict`

**レスポンス** `201 Created`

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": 1,
  "plan_id": 1,
  "schedule_id": 1,
  "status": "confirmed",
  "total_price": 37500,
  "participants": [
    {"participant_type":"adult","label":"大人（18歳以上）","count":2,"unit_price":15000},
    {"participant_type":"child","label":"子供（10〜17歳）","count":1,"unit_price":12000}
  ]
}
```

#### `GET /bookings/:id`

UUID で予約を取得。参加者内訳を含む。

#### `GET /users/:user_id/bookings`

ユーザーの予約一覧。

---

### レビュー

#### `POST /reviews`

```json
{
  "user_id": 1,
  "plan_id": 1,
  "booking_id": "550e8400-...",
  "rating": 5,
  "comment": "最高でした！"
}
```

**バリデーション**: `rating` は 1〜5。レビュー投稿後、施設の `review_avg` / `review_count` がトリガーで自動更新される。

---

### 検索

#### `GET /search`

**クエリパラメータ**

| パラメータ | 型 | 説明 |
|---|---|---|
| q | string | フリーワード（プランタイトル・説明・タグ・施設名を LIKE 検索） |
| area_id | integer | 地域フィルタ |
| category_id | integer | カテゴリフィルタ |
| date | string | YYYY-MM-DD |
| adults | integer | 大人人数 |
| children | integer | 子供人数 |

```json
{
  "plans": [...]
}
```

---

## 認証・セキュリティ

### パスワードハッシュ

PBKDF2-SHA256 を CommonCrypto で実装。

```
保存形式: pbkdf2$<hex-salt(32bytes)>$<hex-dk(32bytes)>
salt: arc4random_buf() で 32 バイト生成
iterations: 100,000
derived key length: 32 バイト
```

### UUID 生成

`arc4random_buf()` で 16 バイト生成後、RFC 4122 v4 のビットフィールドを設定。

### 既知のセキュリティ課題（今後の対応項目）

| 項目 | 説明 | 対策案 |
|---|---|---|
| 認証なし API | ログイン済みチェックがない | JWT または署名付きトークンを実装 |
| IDOR | `/users/:id/bookings` は任意の user_id を指定可能 | トークン検証で自分のデータのみ返す |
| 合計金額クライアント計算 | `total_price` をリクエストで受け取っている | サーバー側で `plan_prices × participants` から算出 |
| LIKE インジェクション | 検索の `%keyword%` に `%`/`_` が含まれると全件マッチ | `%` → `\%`、`_` → `\_` のエスケープ処理 |

---

## テスト

```bash
make test
```

`tests/test_api.c` に統合テスト 26 本を実装。

### テスト実行の仕組み

```
main()
  └─ fork()
       ├─ 子プロセス: execlp("./asoview-c", ランダムポート, tmpDB)
       └─ 親プロセス: wait_for_port() でポートが開くまでポーリング
                     └─ 各テスト関数を順次実行（libcurl で HTTP）
                     └─ kill(pid, SIGTERM) でサーバー停止
```

### テスト一覧

| テスト | 内容 |
|---|---|
| `test_health` | ヘルスエンドポイント |
| `test_list_areas` | 地域一覧 |
| `test_list_categories` | カテゴリ一覧 |
| `test_list_venues` | 施設一覧 |
| `test_list_venues_area_filter` | 地域フィルタ |
| `test_get_venue` | 施設詳細 |
| `test_get_venue_not_found` | 存在しない施設 → 404 |
| `test_list_plans` | プラン一覧 |
| `test_list_plans_filter_category` | カテゴリフィルタ |
| `test_list_plans_filter_date` | 日付・人数フィルタ |
| `test_get_plan` | プラン詳細（価格込み） |
| `test_list_schedules` | スケジュール一覧 |
| `test_list_schedules_by_date` | 日付フィルタ |
| `test_create_user` | ユーザー登録 |
| `test_create_user_duplicate` | 重複メール → 409 |
| `test_create_user_short_password` | 短いパスワード → 400 |
| `test_login` | ログイン成功 |
| `test_login_wrong_password` | 誤パスワード → 401 |
| `test_create_and_get_booking` | 予約作成 + 取得 |
| `test_booking_capacity_check` | 定員超過 → 409 |
| `test_list_user_bookings` | ユーザーの予約一覧 |
| `test_create_review` | レビュー投稿 |
| `test_create_review_invalid_rating` | 不正評価 → 400 |
| `test_search_keyword` | フリーワード検索 |
| `test_search_no_results` | ヒットなし |
| `test_search_area_category` | 地域 + カテゴリ複合検索 |

---

## 設計メモ

### なぜ C か

- 外部ランタイム不要（シングルバイナリ）
- mongoose + cJSON のみで HTTP + JSON を完結
- SQLite が標準搭載の OS では `cc` だけで完結

### スキーマ埋め込みの仕組み

```c
// db.c
static const char *SCHEMA_SQL =
#include "schema_embed.h"
;
```

`schema_embed.h` は `scripts/gen_schema_embed.py` が `schema.sql` を C 文字列リテラル行に変換して生成する。SQLite の `sqlite3_exec()` は複数 SQL ステートメントをまとめて実行できるため、全 DDL を 1 度に投入している。

### ルーティングの注意点

`sscanf(uri, "/api/v1/plans/%ld/schedules", &id)` は URI が `/api/v1/plans/1` でも `1` を返す（sscanf は先頭から一致した数を返すため、末尾の `/schedules` は省略可）。そのため `strstr(uri, "/schedules")` で末尾パスを確認している。
