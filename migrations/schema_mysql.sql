-- MySQL/MariaDB スキーマ (migrations/schema_mysql.sql)
-- 使用方法: mysql -u user -p asoview < schema_mysql.sql

SET NAMES utf8mb4;
SET time_zone = '+09:00';

-- 地域
CREATE TABLE IF NOT EXISTS areas (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    name       VARCHAR(255) NOT NULL,
    name_kana  VARCHAR(255),
    parent_id  INT,
    level      INT NOT NULL DEFAULT 0,
    slug       VARCHAR(128) UNIQUE NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (parent_id) REFERENCES areas(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- カテゴリ
CREATE TABLE IF NOT EXISTS categories (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    name       VARCHAR(255) NOT NULL,
    slug       VARCHAR(128) UNIQUE NOT NULL,
    parent_id  INT,
    icon       VARCHAR(64),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (parent_id) REFERENCES categories(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 施設・拠点
CREATE TABLE IF NOT EXISTS venues (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    name         VARCHAR(255) NOT NULL,
    description  TEXT,
    area_id      INT NOT NULL,
    address      VARCHAR(512),
    latitude     DOUBLE,
    longitude    DOUBLE,
    phone        VARCHAR(32),
    website      VARCHAR(512),
    images       TEXT NOT NULL DEFAULT ('[]'),
    review_count INT NOT NULL DEFAULT 0,
    review_avg   DOUBLE NOT NULL DEFAULT 0.0,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (area_id) REFERENCES areas(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- プラン
CREATE TABLE IF NOT EXISTS plans (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    venue_id         INT NOT NULL,
    category_id      INT NOT NULL,
    title            VARCHAR(512) NOT NULL,
    description      TEXT,
    duration_minutes INT,
    min_participants INT NOT NULL DEFAULT 1,
    max_participants INT,
    min_age          INT,
    images           TEXT NOT NULL DEFAULT ('[]'),
    tags             TEXT NOT NULL DEFAULT ('[]'),
    is_active        TINYINT(1) NOT NULL DEFAULT 1,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (venue_id) REFERENCES venues(id),
    FOREIGN KEY (category_id) REFERENCES categories(id),
    FULLTEXT KEY plans_fulltext (title, description)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 価格
CREATE TABLE IF NOT EXISTS plan_prices (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    plan_id          INT NOT NULL,
    participant_type VARCHAR(32) NOT NULL,
    label            VARCHAR(128) NOT NULL,
    price            INT NOT NULL,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (plan_id) REFERENCES plans(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- スケジュール
CREATE TABLE IF NOT EXISTS schedules (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    plan_id      INT NOT NULL,
    date         VARCHAR(10) NOT NULL,
    start_time   VARCHAR(5) NOT NULL,
    end_time     VARCHAR(5),
    capacity     INT NOT NULL DEFAULT 10,
    booked_count INT NOT NULL DEFAULT 0,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (plan_id) REFERENCES plans(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ユーザー
CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    email         VARCHAR(255) UNIQUE NOT NULL,
    name          VARCHAR(255) NOT NULL,
    phone         VARCHAR(32),
    password_hash VARCHAR(512) NOT NULL,
    failed_logins INT NOT NULL DEFAULT 0,
    locked_until  DATETIME,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 予約
CREATE TABLE IF NOT EXISTS bookings (
    id                       VARCHAR(36) PRIMARY KEY,
    user_id                  INT NOT NULL,
    plan_id                  INT NOT NULL,
    schedule_id              INT NOT NULL,
    status                   VARCHAR(32) NOT NULL DEFAULT 'confirmed',
    total_price              INT NOT NULL,
    note                     TEXT,
    stripe_payment_intent_id VARCHAR(255),
    created_at               DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (plan_id) REFERENCES plans(id),
    FOREIGN KEY (schedule_id) REFERENCES schedules(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 予約参加者内訳
CREATE TABLE IF NOT EXISTS booking_participants (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    booking_id       VARCHAR(36) NOT NULL,
    participant_type VARCHAR(32) NOT NULL,
    label            VARCHAR(128) NOT NULL,
    count            INT NOT NULL,
    unit_price       INT NOT NULL,
    FOREIGN KEY (booking_id) REFERENCES bookings(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- レビュー
CREATE TABLE IF NOT EXISTS reviews (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    booking_id VARCHAR(36),
    user_id    INT NOT NULL,
    plan_id    INT NOT NULL,
    rating     INT NOT NULL CHECK(rating >= 1 AND rating <= 5),
    comment    TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (booking_id) REFERENCES bookings(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (plan_id) REFERENCES plans(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ブックマーク
CREATE TABLE IF NOT EXISTS bookmarks (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT NOT NULL,
    plan_id    INT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_bookmarks (user_id, plan_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (plan_id) REFERENCES plans(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- パスワードリセットトークン
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token      VARCHAR(128) PRIMARY KEY,
    user_id    INT NOT NULL,
    expires_at DATETIME NOT NULL,
    used       TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ウェイトリスト
CREATE TABLE IF NOT EXISTS waitlist (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL,
    schedule_id INT NOT NULL,
    notified    TINYINT(1) NOT NULL DEFAULT 0,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_waitlist (user_id, schedule_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (schedule_id) REFERENCES schedules(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Stripe webhook 冪等性
CREATE TABLE IF NOT EXISTS webhook_events (
    event_id     VARCHAR(64) PRIMARY KEY,
    processed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- JWT ブラックリスト
CREATE TABLE IF NOT EXISTS jwt_blocklist (
    jti        VARCHAR(256) PRIMARY KEY,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- レビュー集計トリガー
DROP TRIGGER IF EXISTS update_venue_review_stats;
DELIMITER //
CREATE TRIGGER update_venue_review_stats
AFTER INSERT ON reviews
FOR EACH ROW
BEGIN
    UPDATE venues SET
        review_count = (SELECT COUNT(*) FROM reviews r JOIN plans p ON p.id = r.plan_id WHERE p.venue_id = (SELECT venue_id FROM plans WHERE id = NEW.plan_id)),
        review_avg   = (SELECT ROUND(AVG(r.rating), 1) FROM reviews r JOIN plans p ON p.id = r.plan_id WHERE p.venue_id = (SELECT venue_id FROM plans WHERE id = NEW.plan_id))
    WHERE id = (SELECT venue_id FROM plans WHERE id = NEW.plan_id);
END//
DELIMITER ;

DROP TRIGGER IF EXISTS update_venue_review_stats_delete;
DELIMITER //
CREATE TRIGGER update_venue_review_stats_delete
AFTER DELETE ON reviews
FOR EACH ROW
BEGIN
    UPDATE venues SET
        review_count = COALESCE((SELECT COUNT(*) FROM reviews r JOIN plans p ON p.id = r.plan_id WHERE p.venue_id = (SELECT venue_id FROM plans WHERE id = OLD.plan_id)), 0),
        review_avg   = COALESCE((SELECT ROUND(AVG(r.rating), 1) FROM reviews r JOIN plans p ON p.id = r.plan_id WHERE p.venue_id = (SELECT venue_id FROM plans WHERE id = OLD.plan_id)), 0.0)
    WHERE id = (SELECT venue_id FROM plans WHERE id = OLD.plan_id);
END//
DELIMITER ;

-- ─── 後方互換マイグレーション（既存 DB への列追加）────────────────────────
-- CREATE TABLE IF NOT EXISTS は新規 DB では全カラムを含むが、
-- 旧スキーマで作られた DB には ALTER TABLE で追加する（エラーは無視）。

SET @db = DATABASE();

SET @q1 = IF(
    (SELECT COUNT(*) FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA=@db AND TABLE_NAME='users' AND COLUMN_NAME='failed_logins') = 0,
    'ALTER TABLE users ADD COLUMN failed_logins INT NOT NULL DEFAULT 0',
    'SELECT 1');
PREPARE s1 FROM @q1; EXECUTE s1; DEALLOCATE PREPARE s1;

SET @q2 = IF(
    (SELECT COUNT(*) FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA=@db AND TABLE_NAME='users' AND COLUMN_NAME='locked_until') = 0,
    'ALTER TABLE users ADD COLUMN locked_until DATETIME',
    'SELECT 1');
PREPARE s2 FROM @q2; EXECUTE s2; DEALLOCATE PREPARE s2;

SET @q3 = IF(
    (SELECT COUNT(*) FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA=@db AND TABLE_NAME='bookings' AND COLUMN_NAME='stripe_payment_intent_id') = 0,
    'ALTER TABLE bookings ADD COLUMN stripe_payment_intent_id VARCHAR(255)',
    'SELECT 1');
PREPARE s3 FROM @q3; EXECUTE s3; DEALLOCATE PREPARE s3;

-- スケジュール booked_count 自動更新
DROP TRIGGER IF EXISTS update_schedule_booked_count;
DELIMITER //
CREATE TRIGGER update_schedule_booked_count
AFTER INSERT ON booking_participants
FOR EACH ROW
BEGIN
    UPDATE schedules SET
        booked_count = booked_count + NEW.count
    WHERE id = (SELECT schedule_id FROM bookings WHERE id = NEW.booking_id);
END//
DELIMITER ;
