#pragma once

/*
 * メール送信モジュール (Resend API)
 *
 * 環境変数:
 *   RESEND_API_KEY  — Resend API キー (re_xxx...)
 *   RESEND_FROM     — 送信元アドレス (default: noreply@asoview.example.com)
 *   FRONTEND_URL    — フロントエンドURL (default: http://localhost:3000)
 *
 * RESEND_API_KEY が未設定の場合はすべての関数が -1 を返してスキップする。
 */

/* 汎用メール送信。返り値: 0=成功, -1=失敗/スキップ */
int send_email(const char *to, const char *subject, const char *html_body);

/* パスワードリセットメール */
void send_password_reset_email(const char *to, const char *reset_token);

/* 予約確定メール */
void send_booking_confirmation_email(const char *to,
                                     const char *booking_id,
                                     const char *plan_title,
                                     const char *date,
                                     const char *start_time,
                                     long total_price);

/* 予約キャンセルメール */
void send_booking_cancellation_email(const char *to,
                                     const char *booking_id,
                                     const char *plan_title,
                                     int refunded);
