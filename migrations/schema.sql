PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- 地域（地方 → 都道府県 → 市区）
CREATE TABLE IF NOT EXISTS areas (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT NOT NULL,
    name_kana TEXT,
    parent_id INTEGER REFERENCES areas(id),
    level     INTEGER NOT NULL DEFAULT 0, -- 0=地方, 1=都道府県, 2=市区
    slug      TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- カテゴリ（アウトドア > ダイビング など）
CREATE TABLE IF NOT EXISTS categories (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT NOT NULL,
    slug      TEXT UNIQUE NOT NULL,
    parent_id INTEGER REFERENCES categories(id),
    icon      TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 施設・拠点
CREATE TABLE IF NOT EXISTS venues (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    description  TEXT,
    area_id      INTEGER NOT NULL REFERENCES areas(id),
    address      TEXT,
    latitude     REAL,
    longitude    REAL,
    phone        TEXT,
    website      TEXT,
    images       TEXT NOT NULL DEFAULT '[]',  -- JSON array of URLs
    review_count INTEGER NOT NULL DEFAULT 0,
    review_avg   REAL NOT NULL DEFAULT 0.0,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- プラン（施設が提供する体験）
CREATE TABLE IF NOT EXISTS plans (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    venue_id         INTEGER NOT NULL REFERENCES venues(id),
    category_id      INTEGER NOT NULL REFERENCES categories(id),
    title            TEXT NOT NULL,
    description      TEXT,
    duration_minutes INTEGER,
    min_participants INTEGER NOT NULL DEFAULT 1,
    max_participants INTEGER,
    min_age          INTEGER,
    images           TEXT NOT NULL DEFAULT '[]',  -- JSON array
    tags             TEXT NOT NULL DEFAULT '[]',  -- JSON array
    is_active        INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 価格（大人・子供・シニア等）
CREATE TABLE IF NOT EXISTS plan_prices (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id          INTEGER NOT NULL REFERENCES plans(id),
    participant_type TEXT NOT NULL, -- 'adult', 'child', 'senior'
    label            TEXT NOT NULL, -- '大人', '子供(3〜12歳)'
    price            INTEGER NOT NULL, -- 円
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- スケジュール（日時・空き枠）
CREATE TABLE IF NOT EXISTS schedules (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id      INTEGER NOT NULL REFERENCES plans(id),
    date         TEXT NOT NULL,       -- YYYY-MM-DD
    start_time   TEXT NOT NULL,       -- HH:MM
    end_time     TEXT,
    capacity     INTEGER NOT NULL DEFAULT 10,
    booked_count INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ユーザー
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    phone         TEXT,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 予約
CREATE TABLE IF NOT EXISTS bookings (
    id                       TEXT PRIMARY KEY,   -- UUID
    user_id                  INTEGER NOT NULL REFERENCES users(id),
    plan_id                  INTEGER NOT NULL REFERENCES plans(id),
    schedule_id              INTEGER NOT NULL REFERENCES schedules(id),
    status                   TEXT NOT NULL DEFAULT 'confirmed', -- pending_payment/confirmed/cancelled
    total_price              INTEGER NOT NULL,
    note                     TEXT,
    stripe_payment_intent_id TEXT,   -- pi_xxx... (Stripe PaymentIntent ID)
    created_at               TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 予約参加者内訳
CREATE TABLE IF NOT EXISTS booking_participants (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_id       TEXT NOT NULL REFERENCES bookings(id),
    participant_type TEXT NOT NULL,
    label            TEXT NOT NULL,
    count            INTEGER NOT NULL,
    unit_price       INTEGER NOT NULL
);

-- 口コミ・レビュー
CREATE TABLE IF NOT EXISTS reviews (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_id TEXT REFERENCES bookings(id),
    user_id    INTEGER NOT NULL REFERENCES users(id),
    plan_id    INTEGER NOT NULL REFERENCES plans(id),
    rating     INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
    comment    TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- お気に入り（プランのブックマーク）
CREATE TABLE IF NOT EXISTS bookmarks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    plan_id    INTEGER NOT NULL REFERENCES plans(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, plan_id)
);

-- パスワードリセットトークン（1時間有効）
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- レビュー更新時に venue の集計を自動更新
CREATE TRIGGER IF NOT EXISTS update_venue_review_stats
AFTER INSERT ON reviews
BEGIN
    UPDATE venues SET
        review_count = (SELECT COUNT(*) FROM reviews r JOIN plans p ON p.id = r.plan_id WHERE p.venue_id = (SELECT venue_id FROM plans WHERE id = NEW.plan_id)),
        review_avg   = (SELECT ROUND(AVG(r.rating), 1) FROM reviews r JOIN plans p ON p.id = r.plan_id WHERE p.venue_id = (SELECT venue_id FROM plans WHERE id = NEW.plan_id))
    WHERE id = (SELECT venue_id FROM plans WHERE id = NEW.plan_id);
END;

-- スケジュール booked_count 自動更新
CREATE TRIGGER IF NOT EXISTS update_schedule_booked_count
AFTER INSERT ON booking_participants
BEGIN
    UPDATE schedules SET
        booked_count = booked_count + NEW.count
    WHERE id = (SELECT schedule_id FROM bookings WHERE id = NEW.booking_id);
END;
