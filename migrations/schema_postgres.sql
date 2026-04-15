-- PostgreSQL スキーマ (migrations/schema_postgres.sql)
-- 使用方法: psql -U user -d asoview -f schema_postgres.sql

-- 地域（地方 → 都道府県 → 市区）
CREATE TABLE IF NOT EXISTS areas (
    id         SERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    name_kana  TEXT,
    parent_id  INTEGER REFERENCES areas(id),
    level      INTEGER NOT NULL DEFAULT 0,
    slug       TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- カテゴリ
CREATE TABLE IF NOT EXISTS categories (
    id         SERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    slug       TEXT UNIQUE NOT NULL,
    parent_id  INTEGER REFERENCES categories(id),
    icon       TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 施設・拠点
CREATE TABLE IF NOT EXISTS venues (
    id           SERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    description  TEXT,
    area_id      INTEGER NOT NULL REFERENCES areas(id),
    address      TEXT,
    latitude     DOUBLE PRECISION,
    longitude    DOUBLE PRECISION,
    phone        TEXT,
    website      TEXT,
    images       TEXT NOT NULL DEFAULT '[]',
    review_count INTEGER NOT NULL DEFAULT 0,
    review_avg   DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- プラン
CREATE TABLE IF NOT EXISTS plans (
    id               SERIAL PRIMARY KEY,
    venue_id         INTEGER NOT NULL REFERENCES venues(id),
    category_id      INTEGER NOT NULL REFERENCES categories(id),
    title            TEXT NOT NULL,
    description      TEXT,
    duration_minutes INTEGER,
    min_participants INTEGER NOT NULL DEFAULT 1,
    max_participants INTEGER,
    min_age          INTEGER,
    images           TEXT NOT NULL DEFAULT '[]',
    tags             TEXT NOT NULL DEFAULT '[]',
    is_active        SMALLINT NOT NULL DEFAULT 1,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 価格
CREATE TABLE IF NOT EXISTS plan_prices (
    id               SERIAL PRIMARY KEY,
    plan_id          INTEGER NOT NULL REFERENCES plans(id),
    participant_type TEXT NOT NULL,
    label            TEXT NOT NULL,
    price            INTEGER NOT NULL,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- スケジュール
CREATE TABLE IF NOT EXISTS schedules (
    id           SERIAL PRIMARY KEY,
    plan_id      INTEGER NOT NULL REFERENCES plans(id),
    date         TEXT NOT NULL,
    start_time   TEXT NOT NULL,
    end_time     TEXT,
    capacity     INTEGER NOT NULL DEFAULT 10,
    booked_count INTEGER NOT NULL DEFAULT 0,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ユーザー
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    phone         TEXT,
    password_hash TEXT NOT NULL,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  TIMESTAMP,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 予約
CREATE TABLE IF NOT EXISTS bookings (
    id                       TEXT PRIMARY KEY,
    user_id                  INTEGER NOT NULL REFERENCES users(id),
    plan_id                  INTEGER NOT NULL REFERENCES plans(id),
    schedule_id              INTEGER NOT NULL REFERENCES schedules(id),
    status                   TEXT NOT NULL DEFAULT 'confirmed',
    total_price              INTEGER NOT NULL,
    note                     TEXT,
    stripe_payment_intent_id TEXT,
    created_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 予約参加者内訳
CREATE TABLE IF NOT EXISTS booking_participants (
    id               SERIAL PRIMARY KEY,
    booking_id       TEXT NOT NULL REFERENCES bookings(id),
    participant_type TEXT NOT NULL,
    label            TEXT NOT NULL,
    count            INTEGER NOT NULL,
    unit_price       INTEGER NOT NULL
);

-- 口コミ・レビュー
CREATE TABLE IF NOT EXISTS reviews (
    id         SERIAL PRIMARY KEY,
    booking_id TEXT REFERENCES bookings(id),
    user_id    INTEGER NOT NULL REFERENCES users(id),
    plan_id    INTEGER NOT NULL REFERENCES plans(id),
    rating     INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
    comment    TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ブックマーク
CREATE TABLE IF NOT EXISTS bookmarks (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    plan_id    INTEGER NOT NULL REFERENCES plans(id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, plan_id)
);

-- パスワードリセットトークン
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    expires_at TIMESTAMP NOT NULL,
    used       SMALLINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ウェイトリスト
CREATE TABLE IF NOT EXISTS waitlist (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    schedule_id INTEGER NOT NULL REFERENCES schedules(id),
    notified    SMALLINT NOT NULL DEFAULT 0,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, schedule_id)
);

-- Stripe webhook 冪等性
CREATE TABLE IF NOT EXISTS webhook_events (
    event_id     TEXT PRIMARY KEY,
    processed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- JWT ブラックリスト
CREATE TABLE IF NOT EXISTS jwt_blocklist (
    jti        TEXT PRIMARY KEY,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 全文検索インデックス（tsvector）
ALTER TABLE plans ADD COLUMN IF NOT EXISTS search_vector tsvector;

CREATE INDEX IF NOT EXISTS plans_search_idx ON plans USING GIN(search_vector);

CREATE OR REPLACE FUNCTION plans_search_update() RETURNS trigger AS $$
BEGIN
    NEW.search_vector :=
        to_tsvector('simple', COALESCE(NEW.title,'') || ' ' || COALESCE(NEW.description,''));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS plans_search_trigger ON plans;
CREATE TRIGGER plans_search_trigger
    BEFORE INSERT OR UPDATE ON plans
    FOR EACH ROW EXECUTE FUNCTION plans_search_update();

-- レビュー集計トリガー
CREATE OR REPLACE FUNCTION update_venue_review_stats() RETURNS trigger AS $$
DECLARE
    vid INTEGER;
BEGIN
    SELECT venue_id INTO vid FROM plans WHERE id = COALESCE(NEW.plan_id, OLD.plan_id);
    UPDATE venues SET
        review_count = (SELECT COUNT(*) FROM reviews r JOIN plans p ON p.id = r.plan_id WHERE p.venue_id = vid),
        review_avg   = COALESCE((SELECT ROUND(AVG(r.rating)::numeric, 1) FROM reviews r JOIN plans p ON p.id = r.plan_id WHERE p.venue_id = vid), 0.0)
    WHERE id = vid;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_venue_review_insert ON reviews;
CREATE TRIGGER trg_venue_review_insert
    AFTER INSERT OR DELETE ON reviews
    FOR EACH ROW EXECUTE FUNCTION update_venue_review_stats();

-- スケジュール booked_count 自動更新
CREATE OR REPLACE FUNCTION update_schedule_booked_count() RETURNS trigger AS $$
BEGIN
    UPDATE schedules SET
        booked_count = booked_count + NEW.count
    WHERE id = (SELECT schedule_id FROM bookings WHERE id = NEW.booking_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_schedule_booked_count ON booking_participants;
CREATE TRIGGER trg_schedule_booked_count
    AFTER INSERT ON booking_participants
    FOR EACH ROW EXECUTE FUNCTION update_schedule_booked_count();

-- ─── 後方互換マイグレーション（既存 DB への列追加）─────────────────────────
-- CREATE TABLE IF NOT EXISTS は新規 DB では全カラムを含むが、
-- 旧スキーマで作られた DB には ALTER TABLE で追加する。

DO $$ BEGIN
    ALTER TABLE users ADD COLUMN IF NOT EXISTS
        failed_logins INTEGER NOT NULL DEFAULT 0;
EXCEPTION WHEN others THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE users ADD COLUMN IF NOT EXISTS
        locked_until TIMESTAMP;
EXCEPTION WHEN others THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE bookings ADD COLUMN IF NOT EXISTS
        stripe_payment_intent_id TEXT;
EXCEPTION WHEN others THEN NULL; END $$;
