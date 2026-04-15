/**
 * Asoview k6 負荷テスト
 *
 * 使い方:
 *   k6 run scripts/load_test.js
 *   k6 run --vus 50 --duration 60s scripts/load_test.js
 *   BASE_URL=http://my-server:3001 k6 run scripts/load_test.js
 *
 * インストール: https://k6.io/docs/get-started/installation/
 *   macOS: brew install k6
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

/* ─── カスタムメトリクス ────────────────────────────────────────────── */
const errorRate   = new Rate('error_rate');
const bookingTime = new Trend('booking_create_duration_ms', true);
const searchTime  = new Trend('plan_search_duration_ms',   true);

/* ─── テスト設定 ────────────────────────────────────────────────────── */
export const options = {
  stages: [
    { duration: '30s', target: 10  },  // ウォームアップ: 0 → 10 VUs
    { duration: '60s', target: 50  },  // 負荷増大: 10 → 50 VUs
    { duration: '60s', target: 50  },  // 定常負荷: 50 VUs x 60s
    { duration: '30s', target: 100 },  // スパイク: 50 → 100 VUs
    { duration: '30s', target: 0   },  // クールダウン: 100 → 0 VUs
  ],
  thresholds: {
    /* p95 レイテンシが 500ms 以下 */
    http_req_duration: ['p(95)<500'],
    /* エラー率が 1% 以下 */
    error_rate: ['rate<0.01'],
    /* 予約作成 p99 が 1000ms 以下 */
    booking_create_duration_ms: ['p(99)<1000'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3001';

/* テスト用ユーザー資格情報（--env で上書き可能） */
const TEST_EMAIL    = __ENV.TEST_EMAIL    || 'load_test@example.com';
const TEST_PASSWORD = __ENV.TEST_PASSWORD || 'Test1234!';

/* ─── セットアップ: テストユーザー登録＆ログイン ────────────────────── */
export function setup() {
  /* ユーザー登録（既存でも OK — 409 は無視） */
  http.post(`${BASE_URL}/api/v1/users`, JSON.stringify({
    name: 'Load Test User',
    email: TEST_EMAIL,
    password: TEST_PASSWORD,
  }), { headers: { 'Content-Type': 'application/json' } });

  /* ログインしてトークン取得 */
  const loginRes = http.post(`${BASE_URL}/api/v1/auth/login`, JSON.stringify({
    email: TEST_EMAIL,
    password: TEST_PASSWORD,
  }), { headers: { 'Content-Type': 'application/json' } });

  if (loginRes.status !== 200) {
    console.error(`ログイン失敗 (${loginRes.status}): ${loginRes.body}`);
    return { token: null, venueId: null, planId: null, scheduleId: null };
  }
  const token = JSON.parse(loginRes.body).token;

  /* テスト用会場/プラン/スケジュールを取得 */
  const venuesRes = http.get(`${BASE_URL}/api/v1/venues?limit=1`);
  const plansRes  = http.get(`${BASE_URL}/api/v1/plans?limit=1`);
  const venues    = JSON.parse(venuesRes.body);
  const plans     = JSON.parse(plansRes.body);

  const venueId = venues.items && venues.items.length > 0 ? venues.items[0].id : null;
  const plan    = plans.items  && plans.items.length  > 0 ? plans.items[0]     : null;
  const planId  = plan ? plan.id : null;

  /* スケジュール取得 */
  let scheduleId = null;
  if (planId) {
    const schedRes = http.get(`${BASE_URL}/api/v1/plans/${planId}/schedules?limit=1`);
    if (schedRes.status === 200) {
      const schedData = JSON.parse(schedRes.body);
      if (schedData.items && schedData.items.length > 0) {
        scheduleId = schedData.items[0].id;
      }
    }
  }

  return { token, venueId, planId, scheduleId };
}

/* ─── メインシナリオ ────────────────────────────────────────────────── */
export default function (data) {
  const { token, venueId, planId, scheduleId } = data;
  const authHeaders = token
    ? { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }
    : { 'Content-Type': 'application/json' };

  /* 各ユーザーがランダムにシナリオを選択 */
  const scenario = Math.random();

  if (scenario < 0.40) {
    /* ─ 40%: 会場・プラン閲覧（読み込み重視） ─ */
    group('browse', () => {
      const r1 = http.get(`${BASE_URL}/api/v1/venues?limit=20`);
      check(r1, { 'venues 200': (r) => r.status === 200 });
      errorRate.add(r1.status !== 200);
      sleep(0.5);

      if (venueId) {
        const r2 = http.get(`${BASE_URL}/api/v1/venues/${venueId}`);
        check(r2, { 'venue detail 200': (r) => r.status === 200 });
        errorRate.add(r2.status !== 200);
      }
      sleep(0.3);
    });

  } else if (scenario < 0.65) {
    /* ─ 25%: プラン検索 ─ */
    group('search', () => {
      const keywords = ['サーフィン', 'カヤック', 'ハイキング', 'ダイビング', 'スキー'];
      const q = keywords[Math.floor(Math.random() * keywords.length)];
      const start = Date.now();
      const r = http.get(`${BASE_URL}/api/v1/plans?q=${encodeURIComponent(q)}&limit=20`);
      searchTime.add(Date.now() - start);
      check(r, { 'search 200': (r) => r.status === 200 });
      errorRate.add(r.status !== 200);
      sleep(0.3);
    });

  } else if (scenario < 0.80) {
    /* ─ 15%: ヘルスチェック + メトリクス ─ */
    group('health', () => {
      const r1 = http.get(`${BASE_URL}/api/v1/health`);
      check(r1, { 'health 200': (r) => r.status === 200 });
      errorRate.add(r1.status !== 200);
    });

  } else if (scenario < 0.93) {
    /* ─ 13%: 予約作成（書き込み） ─ */
    group('booking', () => {
      if (!token || !scheduleId) return;
      const start = Date.now();
      const r = http.post(`${BASE_URL}/api/v1/bookings`, JSON.stringify({
        schedule_id: scheduleId,
        num_people: 1,
      }), { headers: authHeaders });
      bookingTime.add(Date.now() - start);
      /* 200=作成成功, 409=満席, 403=競合 のいずれかが正常 */
      check(r, { 'booking ok': (r) => [200, 201, 409, 403].includes(r.status) });
      errorRate.add(![200, 201, 409, 403].includes(r.status));
      sleep(0.2);
    });

  } else {
    /* ─ 7%: ユーザー自身の予約一覧 ─ */
    group('my_bookings', () => {
      if (!token) return;
      const r = http.get(`${BASE_URL}/api/v1/bookings`, { headers: authHeaders });
      check(r, { 'bookings 200': (r) => r.status === 200 });
      errorRate.add(r.status !== 200);
    });
  }

  sleep(Math.random() * 0.5 + 0.1);  /* 100-600ms のランダム wait */
}

/* ─── 後片付け ──────────────────────────────────────────────────────── */
export function teardown(data) {
  if (data.token) {
    /* ログアウト */
    http.post(`${BASE_URL}/api/v1/auth/logout`, null, {
      headers: { Authorization: `Bearer ${data.token}` },
    });
  }
  console.log('=== 負荷テスト完了 ===');
}
