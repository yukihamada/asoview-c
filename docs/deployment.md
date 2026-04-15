# Deployment Guide

## Prerequisites

- Linux (Ubuntu 22.04 / Debian 12 recommended)
- gcc / make / libcurl-dev / libsqlite3-dev
- Nginx (TLS termination)
- Optional: [Litestream](https://litestream.io/) for SQLite backup

## 1. Build

```bash
git clone <repo>
cd asoview-c
make schema   # schema_embed.h を生成
make          # → ./asoview-c
```

### PostgreSQL / MySQL バックエンド

```bash
# PostgreSQL
make DB=postgres
# MySQL
make DB=mysql
```

### Cross-compile (ARM / musl)

```bash
CC=aarch64-linux-musl-gcc make
```

## 2. Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `JWT_SECRET` | **Required in prod** | insecure default | JWT signing key (≥32 chars) |
| `ADMIN_KEY` | **Required in prod** | insecure default | X-Admin-Key value |
| `PORT` | No | `3001` | Listen port |
| `DATABASE_URL` | No | `asoview.db` | SQLite ファイルパス または `postgres://...` / `mysql://...` URI |
| `CORS_ORIGIN` | No | `*` | 許可するオリジン（例: `https://yourdomain.com`）未設定で警告ログ出力 |
| `RESEND_API_KEY` | No | — | Resend email API key |
| `RESEND_FROM` | No | `noreply@example.com` | From address |
| `FRONTEND_URL` | No | `http://localhost:3000` | パスワードリセットメール内のリンクに使用 |
| `STRIPE_SECRET_KEY` | No | — | Stripe secret key (sk_live_…) |
| `STRIPE_WEBHOOK_SECRET` | No | — | Stripe webhook signing secret (whsec_…) |
| `AWS_ACCESS_KEY_ID` | No | — | S3 画像アップロード用 |
| `AWS_SECRET_ACCESS_KEY` | No | — | S3 画像アップロード用 |
| `AWS_S3_BUCKET` | No | — | S3 バケット名 |
| `AWS_S3_REGION` | No | `ap-northeast-1` | S3 リージョン |
| `MYSQL_HOST` | MySQL時 | `127.0.0.1` | MySQL ホスト（`DB=mysql` ビルド時） |
| `MYSQL_PORT` | MySQL時 | `3306` | MySQL ポート |
| `MYSQL_USER` | MySQL時 | `root` | MySQL ユーザー |
| `MYSQL_PASSWORD` | MySQL時 | — | MySQL パスワード |
| `MYSQL_DATABASE` | MySQL時 | `asoview` | MySQL データベース名 |

Create a `.env` file (never commit this):

```bash
JWT_SECRET=$(openssl rand -hex 32)
ADMIN_KEY=$(openssl rand -hex 24)
RESEND_API_KEY=re_xxxxxxxxxxxx
RESEND_FROM=info@yourdomain.com
FRONTEND_URL=https://yourdomain.com
STRIPE_SECRET_KEY=<your_stripe_secret_key>
STRIPE_WEBHOOK_SECRET=<your_webhook_signing_secret>
DATABASE_URL=/data/asoview.db
```

## 3. systemd Service

### 通常起動

```ini
# /etc/systemd/system/asoview.service
[Unit]
Description=asoview-c API server
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/asoview
EnvironmentFile=/opt/asoview/.env
ExecStart=/opt/asoview/asoview-c
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/data

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now asoview
sudo systemctl status asoview
```

### ゼロダウンタイム再起動（Socket Activation）

systemd の Socket Activation を使うと、再起動中もリスニングソケットを保持し続けるため
接続が切れません（`systemctl restart` 中も TCP 接続を受け付けます）。

```ini
# /etc/systemd/system/asoview.socket
[Unit]
Description=asoview-c HTTP socket

[Socket]
ListenStream=3001
Accept=no
# ソケットをプロセス間で保持（再起動時も接続を失わない）

[Install]
WantedBy=sockets.target
```

```ini
# /etc/systemd/system/asoview.service （Socket Activation 版）
[Unit]
Description=asoview-c API server
Requires=asoview.socket
After=asoview.socket

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/asoview
EnvironmentFile=/opt/asoview/.env
ExecStart=/opt/asoview/asoview-c
Restart=on-failure
RestartSec=1

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/data

[Install]
WantedBy=multi-user.target
```

```bash
# 初回セットアップ
sudo systemctl daemon-reload
sudo systemctl enable --now asoview.socket
sudo systemctl start asoview

# バイナリ更新時のゼロダウンタイム再起動
sudo cp /tmp/asoview-c-new /opt/asoview/asoview-c
sudo systemctl restart asoview   # ソケットは asoview.socket が保持するため切れない
```

## 4. Nginx (TLS Termination)

```nginx
# /etc/nginx/sites-available/asoview
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

    location / {
        proxy_pass         http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
    }
}
```

```bash
sudo certbot --nginx -d yourdomain.com
sudo nginx -t && sudo systemctl reload nginx
```

## 5. SQLite Backup (Litestream)

Litestream は WAL フレームをリアルタイムで S3 / Cloudflare R2 / GCS にストリームします。
RPO ≈ 1 秒、RTO ≈ 数十秒で運用できます。

### インストール

```bash
curl -fsSL https://github.com/benbjohnson/litestream/releases/latest/download/litestream-linux-amd64.tar.gz \
  | sudo tar -C /usr/local/bin -xz litestream
```

### 設定ファイル

Secrets はファイルに直書きせず、systemd の `EnvironmentFile` で渡します。

```yaml
# /etc/litestream.yml
dbs:
  - path: /data/asoview.db
    replicas:
      # ── AWS S3 ──────────────────────────────────────────────────
      - url: s3://${LITESTREAM_S3_BUCKET}/asoview
        access-key-id: ${AWS_ACCESS_KEY_ID}
        secret-access-key: ${AWS_SECRET_ACCESS_KEY}
        region: ${AWS_REGION:-ap-northeast-1}
        # 保持期間: 直近 24 時間はすべてのフレーム、それ以前は 1 時間ごとのスナップショット
        retention: 24h
        snapshot-interval: 1h

      # ── Cloudflare R2（S3 互換）────────────────────────────────
      # - url: s3://${R2_BUCKET}/asoview
      #   endpoint: https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com
      #   access-key-id: ${R2_ACCESS_KEY_ID}
      #   secret-access-key: ${R2_SECRET_ACCESS_KEY}
```

### 環境変数ファイル

```bash
# /opt/asoview/litestream.env  （chmod 600）
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=ap-northeast-1
LITESTREAM_S3_BUCKET=your-bucket
```

### systemd サービス

```ini
# /etc/systemd/system/litestream.service
[Unit]
Description=Litestream — asoview DB リアルタイムバックアップ
After=network.target
# asoview サービスより先に起動し、終了後に停止
Before=asoview.service

[Service]
Type=simple
EnvironmentFile=/opt/asoview/litestream.env
ExecStartPre=/usr/local/bin/litestream restore -if-db-not-exists -config /etc/litestream.yml /data/asoview.db
ExecStart=/usr/local/bin/litestream replicate -config /etc/litestream.yml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now litestream
sudo systemctl enable asoview  # litestream より後に起動
```

> **`ExecStartPre` の restore について**  
> Litestream サービス起動時、DB ファイルが存在しない場合のみ S3 から自動復元します。  
> 新規サーバーへの移行時も `systemctl start litestream` だけで本番 DB が復元されます。

### ポイントインタイムリストア

```bash
# 利用可能なスナップショット一覧
litestream snapshots -config /etc/litestream.yml /data/asoview.db

# 特定時刻に巻き戻す（ISO 8601）
litestream restore -config /etc/litestream.yml \
  -timestamp 2026-04-15T12:00:00Z \
  /data/asoview.db
```

### ヘルスチェック

```bash
# レプリケーション遅延を確認（WAL フレームの未送信数）
litestream databases -config /etc/litestream.yml

# S3 バケット内のオブジェクト確認
aws s3 ls s3://${LITESTREAM_S3_BUCKET}/asoview/ --recursive | tail -5
```

## 6. Docker

```bash
docker build -t asoview-c .
docker run -d \
  --name asoview \
  -p 3001:3001 \
  -v $(pwd)/data:/data \
  --env-file .env \
  asoview-c
```

## 7. Database Migrations

On first start, the server automatically applies `src/schema_embed.h` (embedded SQL).
Re-seeding only happens if the `venues` table is empty.

To apply schema changes to an existing DB:

```bash
sqlite3 /data/asoview.db < migrations/schema.sql
```

## 8. Health Check

```bash
curl https://yourdomain.com/api/v1/health
# {"status":"ok","db":"ok"}
```

## 9. Monitoring

Recommended: [Vector](https://vector.dev/) → Datadog / Loki, or simple journald:

```bash
journalctl -u asoview -f
```

Key log lines to watch:
- `[WARN] JWT_SECRET is not set` — secrets not configured
- `[mailer]` — email send success/failure
- `[stripe]` — Stripe API responses
