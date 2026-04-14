# あそビュー C版 — Activity Booking API in C

asoview.com をモデルにした体験・アクティビティ予約サービスの REST API サーバー。  
C11 + mongoose + SQLite3 のみで構築したシングルバイナリサーバー。

## 特徴

- **C11 single binary** — 外部ランタイム不要、`make && ./asoview-c` で即起動
- **JWT HS256 認証** — CommonCrypto / HMAC-SHA256 をスクラッチ実装
- **SQLite3 WAL** — 組み込みDB、トリガーで評価統計を自動更新
- **サーバー側価格計算** — `plan_prices` テーブルから正確な料金を算出
- **実データ** — asoview.com から取得した12会場22プランを収録

## 技術スタック

| 役割 | ライブラリ |
|---|---|
| HTTP サーバー | [mongoose 7.15](https://github.com/cesanta/mongoose) |
| JSON | [cJSON 1.7.18](https://github.com/DaveGamble/cJSON) |
| DB | SQLite3 (WAL mode) |
| 認証 | JWT HS256 (CommonCrypto) |
| パスワード | PBKDF2-SHA256 (CommonCrypto) |

## クイックスタート

```bash
make
./asoview-c
# http://localhost:3001 で起動
```

### テスト実行

```bash
make test
# 38/38 pass
```

## API 一覧

### 公開エンドポイント

| Method | Path | 説明 |
|--------|------|------|
| GET | `/api/v1/health` | ヘルスチェック |
| GET | `/api/v1/areas` | エリア一覧 |
| GET | `/api/v1/categories` | カテゴリ一覧 |
| GET | `/api/v1/venues` | 会場一覧 |
| GET | `/api/v1/venues/:id` | 会場詳細 |
| GET | `/api/v1/venues/:id/plans` | 会場のプラン一覧 |
| GET | `/api/v1/plans` | プラン一覧（フィルタ: category_id, area_id, date, adults） |
| GET | `/api/v1/plans/:id` | プラン詳細（価格込み） |
| GET | `/api/v1/plans/:id/schedules` | スケジュール一覧 |
| GET | `/api/v1/plans/:id/reviews` | レビュー一覧 |
| GET | `/api/v1/search` | キーワード・エリア・カテゴリ検索 |

### 認証

| Method | Path | 説明 |
|--------|------|------|
| POST | `/api/v1/users` | ユーザー登録 |
| POST | `/api/v1/auth/login` | ログイン → JWT トークン取得 |
| GET | `/api/v1/users/:id` | プロフィール取得 |
| PATCH | `/api/v1/users/:id` | プロフィール更新（JWT必須） |

### 予約（JWT必須）

| Method | Path | 説明 |
|--------|------|------|
| POST | `/api/v1/bookings` | 予約作成（価格はサーバー計算） |
| GET | `/api/v1/bookings/:id` | 予約詳細 |
| PATCH | `/api/v1/bookings/:id/cancel` | 予約キャンセル |
| GET | `/api/v1/users/:id/bookings` | ユーザーの予約一覧 |
| POST | `/api/v1/reviews` | レビュー投稿 |

### 管理 API（`X-Admin-Key` ヘッダー必須）

```
POST   /api/v1/admin/venues
PATCH  /api/v1/admin/venues/:id
DELETE /api/v1/admin/venues/:id

POST   /api/v1/admin/plans
PATCH  /api/v1/admin/plans/:id
DELETE /api/v1/admin/plans/:id   (ソフトデリート)
PUT    /api/v1/admin/plans/:id/prices

POST   /api/v1/admin/plans/:id/schedules
DELETE /api/v1/admin/schedules/:id
```

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

## 環境変数

| 変数 | デフォルト | 説明 |
|---|---|---|
| `PORT` | 3001 | リッスンポート |
| `DATABASE_URL` | asoview.db | SQLite DBパス |
| `JWT_SECRET` | dev-secret | JWT署名シークレット |
| `ADMIN_KEY` | asoview-admin-dev | 管理APIキー |

## 実装メモ

- **JWT**: header.payload.signature を base64url でエンコード。CommonCrypto の `CCHmac` で HMAC-SHA256 を計算。
- **ルーティング**: `sscanf` + `%36[^/]`（スラッシュを含まない36文字）で UUID を抽出。
- **LIKE インジェクション**: `escape_like()` で `%`/`_`/`\` をエスケープ + `ESCAPE '\\'` 句。
- **容量チェック**: `capacity - booked_count >= requested` で予約時に検証、超過は 409。
- **ソフトデリート**: プランは `is_active=0` で論理削除、GET/検索から除外。

## 開発の流れ

```
ユーザー指示 → 実装 → make test (38/38) → GitHub
```

```
1. 初期実装（mongoose + SQLite + cJSON）
2. JWT HS256 認証を追加
3. サーバー側価格計算
4. 予約キャンセルAPI
5. 管理CRUD API（会場・プラン・スケジュール・価格）
6. LIKE インジェクション修正
7. asoview.com 実データでシード更新
8. 不足API追加（レビュー一覧、会場別プラン、ユーザープロフィール）
```
