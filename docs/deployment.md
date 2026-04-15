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
make release
# → ./asoview-c (statically-linked binary)
```

### Cross-compile (ARM / musl)

```bash
CC=aarch64-linux-musl-gcc make release
```

## 2. Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `JWT_SECRET` | **Required in prod** | insecure default | JWT signing key (≥32 chars) |
| `ADMIN_KEY` | **Required in prod** | insecure default | X-Admin-Key value |
| `PORT` | No | `3001` | Listen port |
| `DATABASE_URL` | No | `asoview.db` | SQLite file path |
| `RESEND_API_KEY` | No | — | Resend email API key |
| `RESEND_FROM` | No | `noreply@example.com` | From address |
| `FRONTEND_URL` | No | `http://localhost:3000` | Used in password reset email links |
| `STRIPE_SECRET_KEY` | No | — | Stripe secret key (sk_live_…) |
| `STRIPE_WEBHOOK_SECRET` | No | — | Stripe webhook signing secret (whsec_…) |

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

Litestream streams WAL frames to S3 / GCS in real-time.

```yaml
# /etc/litestream.yml
dbs:
  - path: /data/asoview.db
    replicas:
      - url: s3://your-bucket/asoview
        access-key-id: AKIAIOSFODNN7EXAMPLE
        secret-access-key: xxx
        region: ap-northeast-1
```

```ini
# /etc/systemd/system/litestream.service
[Unit]
Description=Litestream
After=network.target

[Service]
ExecStart=/usr/local/bin/litestream replicate -config /etc/litestream.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### Restore

```bash
litestream restore -config /etc/litestream.yml /data/asoview.db
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
