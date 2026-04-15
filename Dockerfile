FROM debian:bookworm-slim AS builder

# DB バックエンド選択: sqlite (デフォルト) / postgres / mysql
ARG DB=sqlite

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        build-essential libcurl4-openssl-dev python3 \
        libsqlite3-dev \
        libpq-dev \
        default-libmysqlclient-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN make schema && make DB=${DB} all

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

ARG DB=sqlite

# バックエンド別ランタイムライブラリをインストール
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        libcurl4 ca-certificates \
        $([ "$DB" = "sqlite" ]   && echo "libsqlite3-0") \
        $([ "$DB" = "postgres" ] && echo "libpq5") \
        $([ "$DB" = "mysql" ]    && echo "libmariadb3") && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/asoview-c .

# Database volume (SQLite)
VOLUME ["/data"]

ENV DATABASE_URL=/data/asoview.db
ENV PORT=3001

EXPOSE 3001

CMD ["./asoview-c"]
