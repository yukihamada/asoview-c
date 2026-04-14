FROM debian:bookworm-slim AS builder

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        build-essential libsqlite3-dev libcurl4-openssl-dev python3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN make schema && make all

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        libsqlite3-0 libcurl4 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/asoview-c .

# Database volume
VOLUME ["/data"]

ENV DATABASE_URL=/data/asoview.db
ENV PORT=3001

EXPOSE 3001

CMD ["./asoview-c"]
